# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import codecs
import datetime
import numbers


DEFAULT_AUTHOR = {
    'name': b'',
    'email': b'',
}

DEFAULT_DATE = {
    'timestamp': None,
    'offset': 0,
    'neg_utc_offset': None,
}


def backslashescape_errors(exception):
    if isinstance(exception, UnicodeDecodeError):
        bad_data = exception.object[exception.start:exception.end]
        escaped = ''.join(r'\x%02x' % x for x in bad_data)
        return escaped, exception.end

    return codecs.backslashreplace_errors(exception)

codecs.register_error('backslashescape', backslashescape_errors)


def decode_with_escape(value):
    """Decode a bytestring as utf-8, escaping the bytes of invalid utf-8 sequences
    as \\x<hex value>. We also escape NUL bytes as they are invalid in JSON
    strings.
    """
    # escape backslashes
    value = value.replace(b'\\', b'\\\\')
    value = value.replace(b'\x00', b'\\x00')
    return value.decode('utf-8', 'backslashescape')


def encode_with_unescape(value):
    """Encode an unicode string containing \\x<hex> backslash escapes"""
    slices = []
    start = 0
    odd_backslashes = False
    i = 0
    while i < len(value):
        if value[i] == '\\':
            odd_backslashes = not odd_backslashes
        else:
            if odd_backslashes:
                if value[i] != 'x':
                    raise ValueError('invalid escape for %r at position %d' %
                                     (value, i-1))
                slices.append(
                    value[start:i-1].replace('\\\\', '\\').encode('utf-8')
                )
                slices.append(bytes.fromhex(value[i+1:i+3]))

                odd_backslashes = False
                start = i = i + 3
                continue

        i += 1

    slices.append(
        value[start:i].replace('\\\\', '\\').encode('utf-8')
    )

    return b''.join(slices)


def author_to_db(author):
    """Convert a swh-model author to its DB representation.

    Args: a swh-model compatible author
    Returns:
        a dict containing two keys: author and email
    """
    if author is None:
        return DEFAULT_AUTHOR

    return author


def db_to_author(id, name, email):
    """Convert the DB representation of an author to a swh-model author.

    Args:
        id (long): the author's identifier
        name (bytes): the author's name
        email (bytes): the author's email

    Returns:
        a dict with two keys: author and email.
    """

    return {
        'id': id,
        'name': name,
        'email': email,
    }


def git_headers_to_db(git_headers):
    """Convert git headers to their database representation.

    We convert the bytes to unicode by decoding them into utf-8 and replacing
    invalid utf-8 sequences with backslash escapes.

    """
    ret = []
    for key, values in git_headers:
        if isinstance(values, list):
            ret.append([key, [decode_with_escape(value) for value in values]])
        else:
            ret.append([key, decode_with_escape(values)])

    return ret


def db_to_git_headers(db_git_headers):
    ret = []
    for key, values in db_git_headers:
        if isinstance(values, list):
            ret.append([key, [encode_with_unescape(value) for value in values]])
        else:
            ret.append([key, encode_with_unescape(values)])

    return ret


def db_to_date(date, offset, neg_utc_offset):
    """Convert the DB representation of a date to a swh-model compatible date.

    Args:
        date (datetime.datetime): a date pulled out of the database
        offset (int): an integer number of minutes representing an UTC offset
        neg_utc_offset (boolean): whether an utc offset is negative

    Returns:
        a dict with three keys:
            timestamp: a timestamp from UTC
            offset: the number of minutes since UTC
            negative_utc: whether a null UTC offset is negative
    """

    if date is None:
        return None

    return {
        'timestamp': date.timestamp(),
        'offset': offset,
        'negative_utc': neg_utc_offset,
    }


def date_to_db(date_offset):
    """Convert a swh-model date_offset to its DB representation.

    Args: a swh-model compatible date_offset
    Returns:
        a dict with three keys:
            timestamp: a date in ISO format
            offset: the UTC offset in minutes
            neg_utc_offset: a boolean indicating whether a null offset is
                            negative or positive.

    """

    if date_offset is None:
        return DEFAULT_DATE

    if isinstance(date_offset, numbers.Real):
        date_offset = datetime.datetime.fromtimestamp(date_offset,
                                                      tz=datetime.timezone.utc)

    if isinstance(date_offset, datetime.datetime):
        timestamp = date_offset
        utcoffset = date_offset.utcoffset()
        offset = int(utcoffset.total_seconds()) // 60
        neg_utc_offset = False if offset == 0 else None
    else:
        if isinstance(date_offset['timestamp'], numbers.Real):
            timestamp = datetime.datetime.fromtimestamp(
                date_offset['timestamp'], tz=datetime.timezone.utc)
        else:
            timestamp = date_offset['timestamp']
        offset = date_offset['offset']
        neg_utc_offset = date_offset.get('negative_utc', None)

    return {
        'timestamp': timestamp.isoformat(),
        'offset': offset,
        'neg_utc_offset': neg_utc_offset,
    }


def revision_to_db(revision):
    """Convert a swh-model revision to its database representation.
    """

    author = author_to_db(revision['author'])
    date = date_to_db(revision['date'])
    committer = author_to_db(revision['committer'])
    committer_date = date_to_db(revision['committer_date'])

    metadata = revision['metadata']

    if metadata and 'extra_git_headers' in metadata:
        metadata = metadata.copy()
        extra_git_headers = git_headers_to_db(metadata['extra_git_headers'])
        metadata['extra_git_headers'] = extra_git_headers

    return {
        'id': revision['id'],
        'author_name': author['name'],
        'author_email': author['email'],
        'date': date['timestamp'],
        'date_offset': date['offset'],
        'date_neg_utc_offset': date['neg_utc_offset'],
        'committer_name': committer['name'],
        'committer_email': committer['email'],
        'committer_date': committer_date['timestamp'],
        'committer_date_offset': committer_date['offset'],
        'committer_date_neg_utc_offset': committer_date['neg_utc_offset'],
        'type': revision['type'],
        'directory': revision['directory'],
        'message': revision['message'],
        'metadata': metadata,
        'synthetic': revision['synthetic'],
        'parents': [
            {
                'id': revision['id'],
                'parent_id': parent,
                'parent_rank': i,
            } for i, parent in enumerate(revision['parents'])
        ],
    }


def db_to_revision(db_revision):
    """Convert a database representation of a revision to its swh-model
    representation."""

    author = db_to_author(
        db_revision['author_id'],
        db_revision['author_name'],
        db_revision['author_email'],
    )
    date = db_to_date(
        db_revision['date'],
        db_revision['date_offset'],
        db_revision['date_neg_utc_offset'],
    )

    committer = db_to_author(
        db_revision['committer_id'],
        db_revision['committer_name'],
        db_revision['committer_email'],
    )
    committer_date = db_to_date(
        db_revision['committer_date'],
        db_revision['committer_date_offset'],
        db_revision['committer_date_neg_utc_offset']
    )

    metadata = db_revision['metadata']

    if metadata and 'extra_git_headers' in metadata:
        extra_git_headers = db_to_git_headers(metadata['extra_git_headers'])
        metadata['extra_git_headers'] = extra_git_headers

    parents = []
    if 'parents' in db_revision:
        for parent in db_revision['parents']:
            if parent:
                parents.append(parent)

    return {
        'id': db_revision['id'],
        'author': author,
        'date': date,
        'committer': committer,
        'committer_date': committer_date,
        'type': db_revision['type'],
        'directory': db_revision['directory'],
        'message': db_revision['message'],
        'metadata': metadata,
        'synthetic': db_revision['synthetic'],
        'parents': parents,
    }


def release_to_db(release):
    """Convert a swh-model release to its database representation.
    """

    author = author_to_db(release['author'])
    date = date_to_db(release['date'])

    return {
        'id': release['id'],
        'author_name': author['name'],
        'author_email': author['email'],
        'date': date['timestamp'],
        'date_offset': date['offset'],
        'date_neg_utc_offset': date['neg_utc_offset'],
        'name': release['name'],
        'target': release['target'],
        'target_type': release['target_type'],
        'comment': release['message'],
        'synthetic': release['synthetic'],
    }


def db_to_release(db_release):
    """Convert a database representation of a release to its swh-model
    representation.
    """

    author = db_to_author(
        db_release['author_id'],
        db_release['author_name'],
        db_release['author_email'],
    )
    date = db_to_date(
        db_release['date'],
        db_release['date_offset'],
        db_release['date_neg_utc_offset']
    )

    return {
        'author': author,
        'date': date,
        'id': db_release['id'],
        'name': db_release['name'],
        'message': db_release['comment'],
        'synthetic': db_release['synthetic'],
        'target': db_release['target'],
        'target_type': db_release['target_type'],
    }
