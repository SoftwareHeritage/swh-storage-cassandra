# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information


from collections import defaultdict
import datetime
import functools
import itertools
import dateutil.parser
import psycopg2

from . import converters
from .db import Db
from .objstorage import ObjStorage
from .exc import ObjNotFoundError, StorageDBError

from swh.core.hashutil import ALGORITHMS

# Max block size of contents to return
BULK_BLOCK_CONTENT_LEN_MAX = 10000


def db_transaction(meth):
    """decorator to execute Storage methods within DB transactions

    The decorated method must accept a `cur` keyword argument
    """
    @functools.wraps(meth)
    def _meth(self, *args, **kwargs):
        with self.db.transaction() as cur:
            return meth(self, *args, cur=cur, **kwargs)
    return _meth


def db_transaction_generator(meth):
    """decorator to execute Storage methods within DB transactions, while
    returning a generator

    The decorated method must accept a `cur` keyword argument

    """
    @functools.wraps(meth)
    def _meth(self, *args, **kwargs):
        with self.db.transaction() as cur:
            yield from meth(self, *args, cur=cur, **kwargs)
    return _meth


class Storage():
    """SWH storage proxy, encompassing DB and object storage

    """

    def __init__(self, db_conn, obj_root):
        """
        Args:
            db_conn: either a libpq connection string, or a psycopg2 connection
            obj_root: path to the root of the object storage

        """
        try:
            if isinstance(db_conn, psycopg2.extensions.connection):
                self.db = Db(db_conn)
            else:
                self.db = Db.connect(db_conn)
        except psycopg2.OperationalError as e:
            raise StorageDBError(e)

        self.objstorage = ObjStorage(obj_root)

    def content_add(self, content):
        """Add content blobs to the storage

        Note: in case of DB errors, objects might have already been added to
        the object storage and will not be removed. Since addition to the
        object storage is idempotent, that should not be a problem.

        Args:
            content: iterable of dictionaries representing individual pieces of
                content to add. Each dictionary has the following keys:
                - data (bytes): the actual content
                - length (int): content length (default: -1)
                - one key for each checksum algorithm in
                  swh.core.hashutil.ALGORITHMS, mapped to the corresponding
                  checksum
                - status (str): one of visible, hidden, absent
                - reason (str): if status = absent, the reason why
                - origin (int): if status = absent, the origin we saw the
                  content in

        """
        db = self.db

        content_by_status = defaultdict(list)
        for d in content:
            if 'status' not in d:
                d['status'] = 'visible'
            if 'length' not in d:
                d['length'] = -1
            content_by_status[d['status']].append(d)

        content_with_data = content_by_status['visible']
        content_without_data = content_by_status['absent']

        missing_content = set(self.content_missing(content_with_data))
        missing_skipped = set(
            sha1_git for sha1, sha1_git, sha256
            in self.skipped_content_missing(content_without_data))

        with db.transaction() as cur:
            if missing_content:
                # create temporary table for metadata injection
                db.mktemp('content', cur)

                def add_to_objstorage(cont):
                    self.objstorage.add_bytes(cont['data'],
                                              obj_id=cont['sha1'])

                content_filtered = (cont for cont in content_with_data
                                    if cont['sha1'] in missing_content)

                db.copy_to(content_filtered, 'tmp_content',
                           ['sha1', 'sha1_git', 'sha256', 'length', 'status'],
                           cur, item_cb=add_to_objstorage)

                # move metadata in place
                db.content_add_from_temp(cur)

            if missing_skipped:
                missing_filtered = (cont for cont in content_without_data
                                    if cont['sha1_git'] in missing_skipped)
                db.mktemp('skipped_content', cur)
                db.copy_to(missing_filtered, 'tmp_skipped_content',
                           ['sha1', 'sha1_git', 'sha256', 'length',
                            'reason', 'status', 'origin'], cur)

                # move metadata in place
                db.skipped_content_add_from_temp(cur)

    def content_get(self, content):
        """Retrieve in bulk contents and their data.

        Args:
            content: iterables of sha1

        Returns:
            Generates streams of contents as dict with their raw data:
            - sha1: sha1's content
            - data: bytes data of the content

        Raises:
            ValueError in case of too much contents are required.
            cf. BULK_BLOCK_CONTENT_LEN_MAX

        """
        # FIXME: Improve on server module to slice the result
        if len(content) > BULK_BLOCK_CONTENT_LEN_MAX:
            raise ValueError(
                "Send at maximum %s contents." % BULK_BLOCK_CONTENT_LEN_MAX)

        for obj_id in content:
            try:
                data = self.objstorage.get_bytes(obj_id)
            except ObjNotFoundError:
                yield None
                continue

            yield {'sha1': obj_id, 'data': data}

    @db_transaction_generator
    def content_missing(self, content, key_hash='sha1', cur=None):
        """List content missing from storage

        Args:
            content: iterable of dictionaries containing one key for each
                checksum algorithm in swh.core.hashutil.ALGORITHMS, mapped to
                the corresponding checksum, and a length key mapped to the
                content length.
            key_hash: the name of the hash used as key (default: 'sha1')

        Returns:
            an iterable of `key_hash`es missing from the storage

        Raises:
            TODO: an exception when we get a hash collision.

        """
        db = self.db

        keys = ['sha1', 'sha1_git', 'sha256']

        if key_hash not in keys:
            raise ValueError("key_hash should be one of %s" % keys)

        key_hash_idx = keys.index(key_hash)

        # Create temporary table for metadata injection
        db.mktemp('content', cur)

        db.copy_to(content, 'tmp_content', keys + ['length'], cur)

        for obj in db.content_missing_from_temp(cur):
            yield obj[key_hash_idx]

    @db_transaction_generator
    def content_missing_per_sha1(self, contents, cur=None):
        """List content missing from storage based only on sha1.

        Args:
            contents: Iterable of sha1 to check for absence.

        Returns:
            an iterable of `sha1`s missing from the storage.

        Raises:
            TODO: an exception when we get a hash collision.

        """
        db = self.db

        db.store_tmp_bytea(contents, cur)
        for obj in db.content_missing_per_sha1_from_temp(cur):
            yield obj[0]

    @db_transaction_generator
    def skipped_content_missing(self, content, cur=None):
        """List skipped_content missing from storage

        Args:
            content: iterable of dictionaries containing the data for each
                checksum algorithm.

        Returns:
            an iterable of signatures missing from the storage
        """
        keys = ['sha1', 'sha1_git', 'sha256']

        db = self.db

        db.mktemp('skipped_content', cur)
        db.copy_to(content, 'tmp_skipped_content',
                   keys + ['length', 'reason'], cur)

        yield from db.skipped_content_missing_from_temp(cur)

    @db_transaction
    def content_find(self, content, cur=None):
        """Find a content hash in db.

        Args:
            content: a dictionary representing one content hash, mapping
                checksum algorithm names (see swh.core.hashutil.ALGORITHMS) to
                checksum values

        Returns:
            a triplet (sha1, sha1_git, sha256) if the content exist
            or None otherwise.

        Raises:
            ValueError in case the key of the dictionary is not sha1, sha1_git
            nor sha256.

        """
        db = self.db

        if not set(content).intersection(ALGORITHMS):
            raise ValueError('content keys must contain at least one of: '
                             'sha1, sha1_git, sha256')

        c = db.content_find(sha1=content.get('sha1'),
                            sha1_git=content.get('sha1_git'),
                            sha256=content.get('sha256'),
                            cur=cur)
        if c:
            keys = ['sha1', 'sha1_git', 'sha256', 'length', 'ctime', 'status']
            return dict(zip(keys, c))
        return None

    @db_transaction
    def content_find_occurrence(self, content, cur=None):
        """Find the content's occurrence.

        Args:
            content: a dictionary entry representing one content hash.
            The dictionary key is one of swh.core.hashutil.ALGORITHMS.
            The value mapped to the corresponding checksum.

        Returns:
            The occurrence of the content.

        Raises:
            ValueError in case the key of the dictionary is not sha1, sha1_git
            nor sha256.

        """
        db = self.db

        c = self.content_find(content)

        if not c:
            return None

        sha1 = c['sha1']

        found_occ = db.content_find_occurrence(sha1, cur=cur)
        if found_occ:
            keys = ['origin_type', 'origin_url', 'branch', 'target',
                    'target_type', 'path']
            return dict(zip(keys, found_occ))
        return None

    def directory_add(self, directories):
        """Add directories to the storage

        Args:
            directories: iterable of dictionaries representing the individual
                directories to add. Each dict has the following keys:
                - id (sha1_git): the id of the directory to add
                - entries (list): list of dicts for each entry in the
                    directory.  Each dict has the following keys:
                    - name (bytes)
                    - type (one of 'file', 'dir', 'rev'):
                        type of the directory entry (file, directory, revision)
                    - target (sha1_git): id of the object pointed at by the
                          directory entry
                    - perms (int): entry permissions
        """
        dirs = set()
        dir_entries = {
            'file': defaultdict(list),
            'dir': defaultdict(list),
            'rev': defaultdict(list),
        }

        for cur_dir in directories:
            dir_id = cur_dir['id']
            dirs.add(dir_id)
            for src_entry in cur_dir['entries']:
                entry = src_entry.copy()
                entry['dir_id'] = dir_id
                dir_entries[entry['type']][dir_id].append(entry)

        dirs_missing = set(self.directory_missing(dirs))
        if not dirs_missing:
            return

        db = self.db
        with db.transaction() as cur:
            # Copy directory ids
            dirs_missing_dict = ({'id': dir} for dir in dirs_missing)
            db.mktemp('directory', cur)
            db.copy_to(dirs_missing_dict, 'tmp_directory', ['id'], cur)

            # Copy entries
            for entry_type, entry_list in dir_entries.items():
                entries = itertools.chain.from_iterable(
                    entries_for_dir
                    for dir_id, entries_for_dir
                    in entry_list.items()
                    if dir_id in dirs_missing)

                db.mktemp_dir_entry(entry_type)

                db.copy_to(
                    entries,
                    'tmp_directory_entry_%s' % entry_type,
                    ['target', 'name', 'perms', 'dir_id'],
                    cur,
                )

            # Do the final copy
            db.directory_add_from_temp(cur)

    @db_transaction_generator
    def directory_missing(self, directories, cur):
        """List directories missing from storage

        Args: an iterable of directory ids
        Returns: a list of missing directory ids
        """
        db = self.db

        # Create temporary table for metadata injection
        db.mktemp('directory', cur)

        directories_dicts = ({'id': dir} for dir in directories)

        db.copy_to(directories_dicts, 'tmp_directory', ['id'], cur)

        for obj in db.directory_missing_from_temp(cur):
            yield obj[0]

    @db_transaction_generator
    def directory_get(self,
                      directories,
                      cur=None):
        """Get information on directories.

        Args:
            - directories: an iterable of directory ids

        Returns:
            List of directories as dict with keys and associated values.

        """
        db = self.db
        keys = ('id', 'dir_entries', 'file_entries', 'rev_entries')

        db.mktemp('directory', cur)
        db.copy_to(({'id': dir_id} for dir_id in directories),
                   'tmp_directory', ['id'], cur)

        dirs = db.directory_get_from_temp(cur)
        for line in dirs:
            yield dict(zip(keys, line))

    @db_transaction_generator
    def directory_ls(self, directory, recursive=False, cur=None):
        """Get entries for one directory.

        Args:
            - directory: the directory to list entries from.
            - recursive: if flag on, this list recursively from this directory.

        Returns:
            List of entries for such directory.

        """
        db = self.db
        keys = ['dir_id', 'type', 'target', 'name', 'perms', 'status',
                'sha1', 'sha1_git', 'sha256']

        if recursive:
            res_gen = db.directory_walk(directory)
        else:
            res_gen = db.directory_walk_one(directory)

        for line in res_gen:
            yield dict(zip(keys, line))

    @db_transaction
    def directory_entry_get_by_path(self, directory, paths, cur=None):
        """Get the directory entry (either file or dir) from directory with
        path.

        Args:
            - directory: sha1 of the top level directory
            - paths: path to lookup from the top level directory. From left
            (top) to right (bottom).

        Returns:
            The corresponding directory entry if found, None otherwise.

        """
        db = self.db
        keys = ('dir_id', 'type', 'target', 'name', 'perms', 'status',
                'sha1', 'sha1_git', 'sha256')

        res = db.directory_entry_get_by_path(directory, paths, cur)
        if res:
            return dict(zip(keys, res))

    def revision_add(self, revisions):
        """Add revisions to the storage

        Args:
            revisions: iterable of dictionaries representing the individual
                revisions to add. Each dict has the following keys:
                - id (sha1_git): id of the revision to add
                - date (datetime.DateTime): date the revision was written
                - date_offset (int): offset from UTC in minutes the revision
                    was written
                - date_neg_utc_offset (boolean): whether a null date_offset
                    represents a negative UTC offset
                - committer_date (datetime.DateTime): date the revision got
                    added to the origin
                - committer_date_offset (int): offset from UTC in minutes the
                    revision was added to the origin
                - committer_date_neg_utc_offset (boolean): whether a null
                    committer_date_offset represents a negative UTC offset
                - type (one of 'git', 'tar'): type of the revision added
                - directory (sha1_git): the directory the revision points at
                - message (bytes): the message associated with the revision
                - author_name (bytes): the name of the revision author
                - author_email (bytes): the email of the revision author
                - committer_name (bytes): the name of the revision committer
                - committer_email (bytes): the email of the revision committer
                - metadata (jsonb): extra information as dictionary
                - synthetic (bool): revision's nature (tarball, directory
                    creates synthetic revision)
                - parents (list of sha1_git): the parents of this revision
        """
        db = self.db

        revisions_missing = set(self.revision_missing(
            set(revision['id'] for revision in revisions)))

        if not revisions_missing:
            return

        with db.transaction() as cur:
            db.mktemp_revision(cur)

            revisions_filtered = (
                converters.revision_to_db(revision) for revision in revisions
                if revision['id'] in revisions_missing)

            parents_filtered = []

            db.copy_to(
                revisions_filtered, 'tmp_revision',
                ['id', 'date', 'date_offset', 'date_neg_utc_offset',
                 'committer_date', 'committer_date_offset',
                 'committer_date_neg_utc_offset', 'type', 'directory',
                 'message', 'author_name', 'author_email', 'committer_name',
                 'committer_email', 'metadata', 'synthetic'],
                cur,
                lambda rev: parents_filtered.extend(rev['parents']))

            db.revision_add_from_temp(cur)

            db.copy_to(parents_filtered, 'revision_history',
                       ['id', 'parent_id', 'parent_rank'], cur)

    @db_transaction_generator
    def revision_missing(self, revisions, cur):
        """List revisions missing from storage

        Args: an iterable of revision ids
        Returns: a list of missing revision ids
        """
        db = self.db

        # Create temporary table for metadata injection
        db.mktemp('revision', cur)

        revisions_dicts = ({'id': dir, 'type': 'git'} for dir in revisions)

        db.copy_to(revisions_dicts, 'tmp_revision', ['id', 'type'], cur)

        for obj in db.revision_missing_from_temp(cur):
            yield obj[0]

    @db_transaction_generator
    def revision_get(self, revisions, cur):
        """Get all revisions from storage
           Args: an iterable of revision ids
           Returns: an iterable of revisions as dictionaries
                    (or None if the revision doesn't exist)
        """

        keys = ('id', 'date', 'date_offset', 'date_neg_utc_offset',
                'committer_date', 'committer_date_offset',
                'committer_date_neg_utc_offset', 'type', 'directory',
                'message', 'author_id', 'author_name', 'author_email',
                'committer_id', 'committer_name', 'committer_email',
                'metadata', 'synthetic', 'parents')

        db = self.db

        # Create temporary table for metadata injection
        db.mktemp('revision', cur)

        revisions_dicts = ({'id': rev, 'type': 'git'} for rev in revisions)

        db.copy_to(revisions_dicts, 'tmp_revision', ['id', 'type'], cur)

        for line in self.db.revision_get_from_temp(cur):
            data = converters.db_to_revision(dict(zip(keys, line)))
            if not data['type']:
                yield None
                continue
            yield data

    @db_transaction_generator
    def revision_log(self, revisions, limit=None, cur=None):
        """Fetch revision entry from the given root revisions.

        Args:
            - revisions: array of root revision to lookup
            - limit: limitation on the output result. Default to null.

        Yields:
            List of revision log from such revisions root.

        """
        db = self.db

        keys = ['id', 'date', 'date_offset', 'date_neg_utc_offset',
                'committer_date', 'committer_date_offset',
                'committer_date_neg_utc_offset', 'type', 'directory',
                'message', 'author_id', 'author_name', 'author_email',
                'committer_id', 'committer_name', 'committer_email',
                'metadata', 'synthetic', 'parents']

        for line in db.revision_log(revisions, limit, cur):
            data = converters.db_to_revision(dict(zip(keys, line)))
            if not data['type']:
                yield None
                continue
            yield data

    @db_transaction_generator
    def revision_shortlog(self, revisions, limit=None, cur=None):
        """Fetch the shortlog for the given revisions

        Args:
            revisions: list of root revisions to lookup
            limit: depth limitation for the output

        Yields:
            a list of (id, parents) tuples.
        """

        db = self.db

        yield from db.revision_shortlog(revisions, limit, cur)

    @db_transaction_generator
    def revision_log_by(self, origin_id, limit=None, cur=None):
        """Fetch revision entry from the actual origin_id's latest revision.

        """
        db = self.db

        keys = ('id', 'date', 'date_offset', 'date_neg_utc_offset',
                'committer_date', 'committer_date_offset',
                'committer_date_neg_utc_offset', 'type', 'directory',
                'message', 'author_id', 'author_name', 'author_email',
                'committer_id', 'committer_name', 'committer_email',
                'metadata', 'synthetic', 'parents')

        for line in db.revision_log_by(origin_id, limit, cur):
            data = converters.db_to_revision(dict(zip(keys, line)))
            if not data['type']:
                yield None
                continue
            yield data

    def release_add(self, releases):
        """Add releases to the storage

        Args:
            releases: iterable of dictionaries representing the individual
                releases to add. Each dict has the following keys:
                - id (sha1_git): id of the release to add
                - revision (sha1_git): id of the revision the release points
                    to
                - date (datetime.DateTime): the date the release was made
                - date_offset (int): offset from UTC in minutes the release was
                    made
                - date_neg_utc_offset (boolean): whether a null date_offset
                    represents a negative UTC offset
                - name (bytes): the name of the release
                - comment (bytes): the comment associated with the release
                - author_name (bytes): the name of the release author
                - author_email (bytes): the email of the release author
        """
        db = self.db

        release_ids = set(release['id'] for release in releases)
        releases_missing = set(self.release_missing(release_ids))

        if not releases_missing:
            return

        with db.transaction() as cur:
            db.mktemp_release(cur)

            releases_filtered = (
                converters.release_to_db(release) for release in releases
                if release['id'] in releases_missing
            )

            db.copy_to(releases_filtered, 'tmp_release',
                       ['id', 'target', 'target_type', 'date', 'date_offset',
                        'date_neg_utc_offset', 'name', 'comment',
                        'author_name', 'author_email', 'synthetic'],
                       cur)

            db.release_add_from_temp(cur)

    @db_transaction_generator
    def release_missing(self, releases, cur=None):
        """List releases missing from storage

        Args: an iterable of release ids
        Returns: a list of missing release ids
        """
        db = self.db

        # Create temporary table for metadata injection
        db.store_tmp_bytea(releases, cur)

        for obj in db.release_missing_from_temp(cur):
            yield obj[0]

    @db_transaction_generator
    def release_get(self, releases, cur=None):
        """Given a list of sha1, return the releases's information

        Args:
            releases: list of sha1s

        Returns:
            Generates the list of releases dict with the following keys:
            - id: origin's id
            - revision: origin's type
            - url: origin's url
            - lister: lister's uuid
            - project: project's uuid (FIXME, retrieve this information)

        Raises:
            ValueError if the keys does not match (url and type) nor id.

        """
        db = self.db

        keys = ['id', 'target', 'target_type', 'date', 'date_offset',
                'date_neg_utc_offset', 'name', 'comment', 'synthetic',
                'author_id', 'author_name', 'author_email']

        # Create temporary table for metadata injection
        db.store_tmp_bytea(releases, cur)

        for release in db.release_get_from_temp(cur):
            yield converters.db_to_release(dict(zip(keys, release)))

    @db_transaction
    def occurrence_add(self, occurrences, cur=None):
        """Add occurrences to the storage

        Args:
            occurrences: iterable of dictionaries representing the individual
                occurrences to add. Each dict has the following keys:
                - origin (int): id of the origin corresponding to the
                    occurrence
                - branch (str): the reference name of the occurrence
                - target (sha1_git): the id of the object pointed to by
                    the occurrence
                - target_type (str): the type of object pointed to by the
                    occurrence
                - date (datetime.DateTime): the validity date for the given
                    occurrence
        """
        db = self.db

        processed = []
        for occurrence in occurrences:
            if isinstance(occurrence['date'], str):
                occurrence['date'] = dateutil.parser.parse(occurrence['date'])
            processed.append(occurrence)

        db.mktemp_occurrence_history(cur)
        db.copy_to(processed, 'tmp_occurrence_history',
                   ['origin', 'branch', 'target', 'target_type', 'date'], cur)

        db.occurrence_history_add_from_temp(cur)

    @db_transaction_generator
    def occurrence_get(self, origin_id, cur=None):
        """Retrieve occurrence information per origin_id.

        Args:
            origin_id: The occurrence's origin.

        Yields:
            List of occurrences matching criterion.

        """
        db = self.db
        for line in db.occurrence_get(origin_id, cur):
            yield {
                'origin': line[0],
                'branch': line[1],
                'target': line[2],
                'target_type': line[3],
            }

    @db_transaction_generator
    def revision_get_by(self,
                        origin_id,
                        branch_name=None,
                        timestamp=None,
                        limit=None,
                        cur=None):
        """Given an origin_id, retrieve occurrences' list per given criterions.

        Args:
            origin_id: The origin to filter on.
            branch_name: optional branch name.
            timestamp:
            limit:

        Yields:
            List of occurrences matching the criterions or None if nothing is
            found.

        """
        keys = ('id', 'date', 'date_offset', 'date_neg_utc_offset',
                'committer_date', 'committer_date_offset',
                'committer_date_neg_utc_offset', 'type', 'directory',
                'message', 'author_id', 'author_name', 'author_email',
                'committer_id', 'committer_name', 'committer_email',
                'metadata', 'synthetic', 'parents')

        for line in self.db.revision_get_by(origin_id,
                                            branch_name,
                                            timestamp,
                                            limit=limit,
                                            cur=cur):
            data = converters.db_to_revision(dict(zip(keys, line)))
            if not data['type']:
                yield None
                continue
            yield data

    def release_get_by(self, origin_id, limit=None):
        """Given an origin id, return all the tag objects pointing to heads of
        origin_id.

        Args:
            origin_id: the origin to filter on.
            limit: None by default

        Yields:
            List of releases matching the criterions or None if nothing is
            found.

        """
        keys = ('id', 'target', 'target_type', 'date', 'date_offset',
                'date_neg_utc_offset', 'name', 'comment', 'synthetic',
                'author_id', 'author_name', 'author_email')

        for line in self.db.release_get_by(origin_id, limit=limit):
            data = converters.db_to_release(dict(zip(keys, line)))
            yield data

    @db_transaction
    def origin_get(self, origin, cur=None):
        """Return the origin either identified by its id or its tuple
        (type, url).

        Args:
            origin: dictionary representing the individual
                origin to find.
                This dict has either the keys type and url:
                - type (FIXME: enum TBD): the origin type ('git', 'wget', ...)
                - url (bytes): the url the origin points to
                either the id:
                - id: the origin id

        Returns:
            the origin dict with the keys:
            - id: origin's id
            - type: origin's type
            - url: origin's url
            - lister: lister's uuid
            - project: project's uuid (FIXME, retrieve this information)

        Raises:
            ValueError if the keys does not match (url and type) nor id.

        """
        db = self.db

        keys = ['id', 'type', 'url', 'lister', 'project']

        origin_id = origin.get('id')
        if origin_id:  # check lookup per id first
            ori = db.origin_get(origin_id, cur)
        elif 'type' in origin and 'url' in origin:  # or lookup per type, url
            ori = db.origin_get_with(origin['type'], origin['url'], cur)
        else:  # unsupported lookup
            raise ValueError('Origin must have either id or (type and url).')

        if ori:
            return dict(zip(keys, ori))
        return None

    @db_transaction
    def _person_add(self, person, cur=None):
        """Add a person in storage.

        BEWARE: Internal function for now.
        Do not do anything fancy in case a person already exists.
        Please adapt code if more checks are needed.

        Args:
            person dictionary with keys name and email.

        Returns:
            Id of the new person.

        """
        db = self.db

        return db.person_add(person['name'], person['email'])

    @db_transaction_generator
    def person_get(self, person, cur=None):
        """Return the persons identified by their ids.

        Args:
            person: array of ids.

        Returns:
            The array of persons corresponding of the ids.

        """
        db = self.db

        keys = ['id', 'name', 'email']

        for person in db.person_get(person):
            yield dict(zip(keys, person))

    @db_transaction
    def origin_add_one(self, origin, cur=None):
        """Add origin to the storage

        Args:
            origin: dictionary representing the individual
                origin to add. This dict has the following keys:
                - type (FIXME: enum TBD): the origin type ('git', 'wget', ...)
                - url (bytes): the url the origin points to

        Returns:
            the id of the added origin, or of the identical one that already
            exists.

        """
        db = self.db

        data = db.origin_get_with(origin['type'], origin['url'], cur)
        if data:
            return data[0]

        return db.origin_add(origin['type'], origin['url'], cur)

    @db_transaction
    def fetch_history_start(self, origin_id, cur=None):
        """Add an entry for origin origin_id in fetch_history. Returns the id
        of the added fetch_history entry
        """
        fetch_history = {
            'origin': origin_id,
            'date': datetime.datetime.now(tz=datetime.timezone.utc),
        }

        return self.db.create_fetch_history(fetch_history, cur)

    @db_transaction
    def fetch_history_end(self, fetch_history_id, data, cur=None):
        """Close the fetch_history entry with id `fetch_history_id`, replacing
           its data with `data`.
        """
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        fetch_history = self.db.get_fetch_history(fetch_history_id, cur)

        if not fetch_history:
            raise ValueError('No fetch_history with id %d' % fetch_history_id)

        fetch_history['duration'] = now - fetch_history['date']

        fetch_history.update(data)

        self.db.update_fetch_history(fetch_history, cur)

    @db_transaction
    def fetch_history_get(self, fetch_history_id, cur=None):
        """Get the fetch_history entry with id `fetch_history_id`.
        """
        return self.db.get_fetch_history(fetch_history_id, cur)

    @db_transaction
    def entity_add(self, entities, cur=None):
        """Add the given entitites to the database (in entity_history).

        Args:
            - entities: iterable of dictionaries containing the following keys:
                - uuid (uuid): id of the entity
                - parent (uuid): id of the parent entity
                - name (str): name of the entity
                - type (str): type of entity (one of 'organization',
                    'group_of_entities', 'hosting', 'group_of_persons',
                    'person', 'project')
                - description (str, optional): description of the entity
                - homepage (str): url of the entity's homepage
                - active (bool): whether the entity is active
                - generated (bool): whether the entity was generated
                - lister (uuid): the uuid of the generating entity
                - lister_metadata (dict): lister-specific entity metadata
                - doap (dict): DOAP data for the entity
                - validity (datetime.DateTime array): timestamps at which we
                    listed the entity.
        """
        db = self.db

        cols = list(db.entity_history_cols)
        cols.remove('id')

        db.mktemp_entity_history()
        db.copy_to(entities, 'tmp_entity_history', cols, cur)
        db.entity_history_add_from_temp()

    @db_transaction_generator
    def entity_get_from_lister_metadata(self, entities, cur=None):
        """Fetch entities from the database, matching with the lister and
           associated metadata.

        Args:
            - entities: iterable of dictionaries containing the following keys:
                - lister (uuid): uuid of the lister
                - lister_metadata (dict): subset of the lister metadata used
                  for matching the entity

        Returns:
            A generator of fetched entities with all their attributes. If no
            match was found, the returned entity's uuid is None.
        """

        db = self.db

        db.mktemp_entity_lister(cur)

        mapped_entities = []
        for i, entity in enumerate(entities):
            mapped_entity = entity.copy()
            mapped_entity['id'] = i
            mapped_entities.append(mapped_entity)

        db.copy_to(mapped_entities, 'tmp_entity_lister',
                   ['id', 'lister', 'lister_metadata'], cur)

        cur.execute('''select id, %s
                       from swh_entity_from_tmp_entity_lister()
                       order by id''' %
                    ','.join(db.entity_cols))

        for id, *entity_vals in cur:
            returned_entity = entities[id].copy()
            fetched_entity = dict(zip(db.entity_cols, entity_vals))
            returned_entity['uuid'] = fetched_entity['uuid']
            if fetched_entity['uuid']:
                returned_entity.update(fetched_entity)
            yield returned_entity

    @db_transaction_generator
    def entity_get(self, uuid, cur=None):
        """Returns the list of entity per its uuid identifier and also its
        parent hierarchy.

        Args:
            uuid: entity's identifier

        Returns:
            List of entities starting with entity with uuid and the parent
            hierarchy from such entity.

        """
        db = self.db
        for entity in db.entity_get(uuid, cur):
            yield dict(zip(db.entity_cols, entity))

    @db_transaction
    def stat_counters(self, cur=None):
        """compute statistics about the number of tuples in various tables

        Returns:
            a dictionary mapping textual labels (e.g., content) to integer
            values (e.g., the number of tuples in table content)

        """
        return {k: v for (k, v) in self.db.stat_counters()}
