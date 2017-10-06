# Copyright (C) 2015-2017  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information


from collections import defaultdict
import datetime
import itertools
import json
import dateutil.parser
import psycopg2

from . import converters
from .common import db_transaction_generator, db_transaction
from .db import Db
from .exc import StorageDBError

from swh.model.hashutil import ALGORITHMS
from swh.objstorage import get_objstorage
from swh.objstorage.exc import ObjNotFoundError

# Max block size of contents to return
BULK_BLOCK_CONTENT_LEN_MAX = 10000


CONTENT_HASH_KEYS = ['sha1', 'sha1_git', 'sha256', 'blake2s256']


class Storage():
    """SWH storage proxy, encompassing DB and object storage

    """

    def __init__(self, db, objstorage):
        """
        Args:
            db_conn: either a libpq connection string, or a psycopg2 connection
            obj_root: path to the root of the object storage

        """
        try:
            if isinstance(db, psycopg2.extensions.connection):
                self.db = Db(db)
            else:
                self.db = Db.connect(db)
        except psycopg2.OperationalError as e:
            raise StorageDBError(e)

        self.objstorage = get_objstorage(**objstorage)

    def check_config(self, *, check_write):
        """Check that the storage is configured and ready to go."""

        if not self.objstorage.check_config(check_write=check_write):
            return False

        # Check permissions on one of the tables
        with self.db.transaction() as cur:
            if check_write:
                check = 'INSERT'
            else:
                check = 'SELECT'

            cur.execute(
                "select has_table_privilege(current_user, 'content', %s)",
                (check,)
            )
            return cur.fetchone()[0]

        return True

    def content_add(self, content):
        """Add content blobs to the storage

        Note: in case of DB errors, objects might have already been added to
        the object storage and will not be removed. Since addition to the
        object storage is idempotent, that should not be a problem.

        Args:
            content (iterable): iterable of dictionaries representing
                individual pieces of content to add. Each dictionary has the
                following keys:

                - data (bytes): the actual content
                - length (int): content length (default: -1)
                - one key for each checksum algorithm in
                  :data:`swh.model.hashutil.ALGORITHMS`, mapped to the
                  corresponding checksum
                - status (str): one of visible, hidden, absent
                - reason (str): if status = absent, the reason why
                - origin (int): if status = absent, the origin we saw the
                  content in

        """
        db = self.db

        def _unique_key(hash, keys=CONTENT_HASH_KEYS):
            """Given a hash (tuple or dict), return a unique key from the
               aggregation of keys.

            """
            if isinstance(hash, tuple):
                return hash
            return tuple([hash[k] for k in keys])

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
        missing_skipped = set(_unique_key(hashes) for hashes
                              in self.skipped_content_missing(
                                  content_without_data))

        with db.transaction() as cur:
            if missing_content:
                # create temporary table for metadata injection
                db.mktemp('content', cur)

                def add_to_objstorage(cont):
                    self.objstorage.add(cont['data'],
                                        obj_id=cont['sha1'])

                content_filtered = (cont for cont in content_with_data
                                    if cont['sha1'] in missing_content)

                db.copy_to(content_filtered, 'tmp_content',
                           db.content_get_metadata_keys,
                           cur, item_cb=add_to_objstorage)

                # move metadata in place
                db.content_add_from_temp(cur)

            if missing_skipped:
                missing_filtered = (cont for cont in content_without_data
                                    if _unique_key(cont) in missing_skipped)

                db.mktemp('skipped_content', cur)
                db.copy_to(missing_filtered, 'tmp_skipped_content',
                           db.skipped_content_keys, cur)

                # move metadata in place
                db.skipped_content_add_from_temp(cur)

    @db_transaction
    def content_update(self, content, keys=[], cur=None):
        """Update content blobs to the storage. Does nothing for unknown
        contents or skipped ones.

        Args:
            content (iterable): iterable of dictionaries representing
                individual pieces of content to update. Each dictionary has the
                following keys:

                - data (bytes): the actual content
                - length (int): content length (default: -1)
                - one key for each checksum algorithm in
                  :data:`swh.model.hashutil.ALGORITHMS`, mapped to the
                  corresponding checksum
                - status (str): one of visible, hidden, absent

            keys (list): List of keys (str) whose values needs an update, e.g.,
                new hash column

        """
        db = self.db

        # TODO: Add a check on input keys. How to properly implement
        # this? We don't know yet the new columns.

        db.mktemp('content')
        select_keys = list(set(db.content_get_metadata_keys).union(set(keys)))
        db.copy_to(content, 'tmp_content', select_keys, cur)
        db.content_update_from_temp(keys_to_update=keys,
                                    cur=cur)

    def content_get(self, content):
        """Retrieve in bulk contents and their data.

        Args:
            content: iterables of sha1

        Yields:
            dict: Generates streams of contents as dict with their raw data:

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
                data = self.objstorage.get(obj_id)
            except ObjNotFoundError:
                yield None
                continue

            yield {'sha1': obj_id, 'data': data}

    @db_transaction_generator
    def content_get_metadata(self, content, cur=None):
        """Retrieve content metadata in bulk

        Args:
            content: iterable of content identifiers (sha1)

        Returns:
            an iterable with content metadata corresponding to the given ids
        """
        db = self.db

        db.store_tmp_bytea(content, cur)

        for content_metadata in db.content_get_metadata_from_temp(cur):
            yield dict(zip(db.content_get_metadata_keys, content_metadata))

    @db_transaction_generator
    def content_missing(self, content, key_hash='sha1', cur=None):
        """List content missing from storage

        Args:
            content: iterable of dictionaries containing one key for each
                checksum algorithm in :data:`swh.model.hashutil.ALGORITHMS`,
                mapped to the corresponding checksum, and a length key mapped
                to the content length.
            key_hash: the name of the hash used as key (default: 'sha1')

        Returns:
            iterable: missing ids

        Raises:
            TODO: an exception when we get a hash collision.

        """
        db = self.db

        keys = CONTENT_HASH_KEYS

        if key_hash not in CONTENT_HASH_KEYS:
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
            iterable: missing ids

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
            iterable: missing signatures

        """
        keys = CONTENT_HASH_KEYS

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
                checksum algorithm names (see swh.model.hashutil.ALGORITHMS) to
                checksum values

        Returns:
            a triplet (sha1, sha1_git, sha256) if the content exist
            or None otherwise.

        Raises:
            ValueError: in case the key of the dictionary is not sha1, sha1_git
                nor sha256.

        """
        db = self.db

        if not set(content).intersection(ALGORITHMS):
            raise ValueError('content keys must contain at least one of: '
                             'sha1, sha1_git, sha256, blake2s256')

        c = db.content_find(sha1=content.get('sha1'),
                            sha1_git=content.get('sha1_git'),
                            sha256=content.get('sha256'),
                            blake2s256=content.get('blake2s256'),
                            cur=cur)
        if c:
            return dict(zip(db.content_find_cols, c))
        return None

    @db_transaction_generator
    def content_find_provenance(self, content, cur=None):
        """Find content's provenance information.

        Args:
            content: a dictionary entry representing one content hash.  The
                dictionary key is one of :data:`swh.model.hashutil.ALGORITHMS`.
                The value mapped to the corresponding checksum.

        Yields:
            The provenance information on content.

        """
        db = self.db

        c = self.content_find(content)

        if not c:
            return []

        sha1_git = c['sha1_git']

        for provenance in db.content_find_provenance(sha1_git, cur=cur):
            yield dict(zip(db.provenance_cols, provenance))

    def directory_add(self, directories):
        """Add directories to the storage

        Args:
            directories (iterable): iterable of dictionaries representing the
                individual directories to add. Each dict has the following
                keys:

                - id (sha1_git): the id of the directory to add
                - entries (list): list of dicts for each entry in the
                      directory.  Each dict has the following keys:

                      - name (bytes)
                      - type (one of 'file', 'dir', 'rev'): type of the
                        directory entry (file, directory, revision)
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

        Args:
            directories (iterable): an iterable of directory ids

        Yields:
            missing directory ids

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

        if recursive:
            res_gen = db.directory_walk(directory, cur=cur)
        else:
            res_gen = db.directory_walk_one(directory, cur=cur)

        for line in res_gen:
            yield dict(zip(db.directory_ls_cols, line))

    @db_transaction
    def directory_entry_get_by_path(self, directory, paths, cur=None):
        """Get the directory entry (either file or dir) from directory with path.

        Args:
            - directory: sha1 of the top level directory
            - paths: path to lookup from the top level directory. From left
              (top) to right (bottom).

        Returns:
            The corresponding directory entry if found, None otherwise.

        """
        db = self.db

        res = db.directory_entry_get_by_path(directory, paths, cur)
        if res:
            return dict(zip(db.directory_ls_cols, res))

    @db_transaction
    def cache_content_revision_add(self, revisions, cur=None):
        """Cache the current revision's current targeted arborescence directory.  If
        the revision has already been cached, it just does nothing.

        Args:
            revisions: the revisions to cache

        Returns:
            None

        """
        db = self.db

        db.store_tmp_bytea(revisions, cur)
        db.cache_content_revision_add()

    @db_transaction_generator
    def cache_content_get_all(self, cur=None):
        """Read the distinct contents in the cache table.

        Yields:
            contents from cache

        """
        for content in self.db.cache_content_get_all(cur):
            yield dict(zip(self.db.cache_content_get_cols, content))

    @db_transaction
    def cache_content_get(self, content, cur=None):
        """Retrieve information on content.

        Args:
            content (dict): content with checkums

        Returns:
            Content properties (sha1, sha1_git, sha256, revision_paths)

        """
        if 'sha1_git' in content:
            sha1_git = content['sha1_git']
        else:
            c = self.content_find(content)
            if not c:
                return None
            sha1_git = c['sha1_git']

        c = self.db.cache_content_get(sha1_git, cur=cur)
        if not c:
            return None
        return dict(zip(self.db.cache_content_get_cols, c))

    @db_transaction_generator
    def cache_revision_origin_add(self, origin, visit, cur=None):
        """Cache the list of revisions the given visit added to the origin.

        Args:
            origin: the id of the origin
            visit: the id of the visit

        Returns:
            The list of new revisions

        """
        for (revision,) in self.db.cache_revision_origin_add(origin, visit):
            yield revision

    def revision_add(self, revisions):
        """Add revisions to the storage

        Args:
            revisions (iterable): iterable of dictionaries representing the
                individual revisions to add. Each dict has the following keys:

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
                revisions_filtered, 'tmp_revision', db.revision_add_cols,
                cur,
                lambda rev: parents_filtered.extend(rev['parents']))

            db.revision_add_from_temp(cur)

            db.copy_to(parents_filtered, 'revision_history',
                       ['id', 'parent_id', 'parent_rank'], cur)

    @db_transaction_generator
    def revision_missing(self, revisions, cur=None):
        """List revisions missing from storage

        Args:
            revisions (iterable): revision ids

        Yields:
            missing revision ids

        """
        db = self.db

        db.store_tmp_bytea(revisions, cur)

        for obj in db.revision_missing_from_temp(cur):
            yield obj[0]

    @db_transaction_generator
    def revision_get(self, revisions, cur):
        """Get all revisions from storage

        Args:
            revisions: an iterable of revision ids

        Returns:
            iterable: an iterable of revisions as dictionaries (or None if the
                revision doesn't exist)

        """

        db = self.db

        db.store_tmp_bytea(revisions, cur)

        for line in self.db.revision_get_from_temp(cur):
            data = converters.db_to_revision(
                dict(zip(db.revision_get_cols, line))
            )
            if not data['type']:
                yield None
                continue
            yield data

    @db_transaction_generator
    def revision_log(self, revisions, limit=None, cur=None):
        """Fetch revision entry from the given root revisions.

        Args:
            revisions: array of root revision to lookup
            limit: limitation on the output result. Default to None.

        Yields:
            List of revision log from such revisions root.

        """
        db = self.db

        for line in db.revision_log(revisions, limit, cur):
            data = converters.db_to_revision(
                dict(zip(db.revision_get_cols, line))
            )
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
    def revision_log_by(self, origin_id, branch_name=None, timestamp=None,
                        limit=None, cur=None):
        """Fetch revision entry from the actual origin_id's latest revision.

        Args:
            origin_id: the origin id from which deriving the revision
            branch_name: (optional) occurrence's branch name
            timestamp: (optional) occurrence's time
            limit: (optional) depth limitation for the
                output. Default to None.

        Yields:
            The revision log starting from the revision derived from
            the (origin, branch_name, timestamp) combination if any.

        Returns:
            None if no revision matching this combination is found.

        """
        db = self.db

        # Retrieve the revision by criterion
        revisions = list(db.revision_get_by(
            origin_id, branch_name, timestamp, limit=1))

        if not revisions:
            return None

        revision_id = revisions[0][0]
        # otherwise, retrieve the revision log from that revision
        yield from self.revision_log([revision_id], limit)

    def release_add(self, releases):
        """Add releases to the storage

        Args:
            releases (iterable): iterable of dictionaries representing the
                individual releases to add. Each dict has the following keys:

                - id (sha1_git): id of the release to add
                - revision (sha1_git): id of the revision the release points to
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

            db.copy_to(releases_filtered, 'tmp_release', db.release_add_cols,
                       cur)

            db.release_add_from_temp(cur)

    @db_transaction_generator
    def release_missing(self, releases, cur=None):
        """List releases missing from storage

        Args:
            releases: an iterable of release ids

        Returns:
            a list of missing release ids

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

        Yields:
            releases: list of releases as dicts with the following keys:

            - id: origin's id
            - revision: origin's type
            - url: origin's url
            - lister: lister's uuid
            - project: project's uuid (FIXME, retrieve this information)

        Raises:
            ValueError: if the keys does not match (url and type) nor id.

        """
        db = self.db

        # Create temporary table for metadata injection
        db.store_tmp_bytea(releases, cur)

        for release in db.release_get_from_temp(cur):
            yield converters.db_to_release(
                dict(zip(db.release_get_cols, release))
            )

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

        """
        db = self.db

        db.mktemp_occurrence_history(cur)
        db.copy_to(occurrences, 'tmp_occurrence_history',
                   ['origin', 'branch', 'target', 'target_type', 'visit'], cur)

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

    @db_transaction
    def origin_visit_add(self, origin, ts, cur=None):
        """Add an origin_visit for the origin at ts with status 'ongoing'.

        Args:
            origin: Visited Origin id
            ts: timestamp of such visit

        Returns:
            dict: dictionary with keys origin and visit where:

            - origin: origin identifier
            - visit: the visit identifier for the new visit occurrence
            - ts (datetime.DateTime): the visit date

        """
        if isinstance(ts, str):
            ts = dateutil.parser.parse(ts)

        return {
            'origin': origin,
            'visit': self.db.origin_visit_add(origin, ts, cur)
        }

    @db_transaction
    def origin_visit_update(self, origin, visit_id, status, metadata=None,
                            cur=None):
        """Update an origin_visit's status.

        Args:
            origin: Visited Origin id
            visit_id: Visit's id
            status: Visit's new status
            metadata: Data associated to the visit

        Returns:
            None

        """
        return self.db.origin_visit_update(origin, visit_id, status, metadata,
                                           cur)

    @db_transaction_generator
    def origin_visit_get(self, origin, last_visit=None, limit=None, cur=None):
        """Retrieve all the origin's visit's information.

        Args:
            origin (int): The occurrence's origin (identifier).
            last_visit (int): Starting point from which listing the next visits
                Default to None
            limit (int): Number of results to return from the last visit.
                Default to None

        Yields:
            List of visits.

        """
        db = self.db
        for line in db.origin_visit_get_all(
                origin, last_visit=last_visit, limit=limit, cur=cur):
            data = dict(zip(self.db.origin_visit_get_cols, line))
            yield data

    @db_transaction
    def origin_visit_get_by(self, origin, visit, cur=None):
        """Retrieve origin visit's information.

        Args:
            origin: The occurrence's origin (identifier).

        Returns:
            The information on that particular (origin, visit)

        """
        db = self.db

        ori_visit = db.origin_visit_get(origin, visit, cur)
        if not ori_visit:
            return None

        ori_visit = dict(zip(self.db.origin_visit_get_cols, ori_visit))

        occs = {}
        for occ in db.occurrence_by_origin_visit(origin, visit):
            _, branch_name, target, target_type = occ
            occs[branch_name] = {
                'target': target,
                'target_type': target_type
            }

        ori_visit.update({
            'occurrences': occs
        })

        return ori_visit

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
            branch_name: (optional) branch name.
            timestamp: (optional) time.
            limit: (optional) limit

        Yields:
            List of occurrences matching the criterions or None if nothing is
            found.

        """
        for line in self.db.revision_get_by(origin_id,
                                            branch_name,
                                            timestamp,
                                            limit=limit,
                                            cur=cur):
            data = converters.db_to_revision(
                dict(zip(self.db.revision_get_cols, line))
            )
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

        for line in self.db.release_get_by(origin_id, limit=limit):
            data = converters.db_to_release(
                dict(zip(self.db.release_get_cols, line))
            )
            yield data

    @db_transaction
    def object_find_by_sha1_git(self, ids, cur=None):
        """Return the objects found with the given ids.

        Args:
            ids: a generator of sha1_gits

        Returns:
            dict: a mapping from id to the list of objects found. Each object
            found is itself a dict with keys:

            - sha1_git: the input id
            - type: the type of object found
            - id: the id of the object found
            - object_id: the numeric id of the object found.

        """
        db = self.db

        ret = {id: [] for id in ids}

        for retval in db.object_find_by_sha1_git(ids):
            if retval[1]:
                ret[retval[0]].append(dict(zip(db.object_find_by_sha1_git_cols,
                                               retval)))

        return ret

    @db_transaction
    def origin_get(self, origin, cur=None):
        """Return the origin either identified by its id or its tuple
        (type, url).

        Args:
            origin: dictionary representing the individual origin to find.
                This dict has either the keys type and url:

                - type (FIXME: enum TBD): the origin type ('git', 'wget', ...)
                - url (bytes): the url the origin points to

                or the id:

                - id: the origin id

        Returns:
            dict: the origin dictionary with the keys:

            - id: origin's id
            - type: origin's type
            - url: origin's url
            - lister: lister's uuid
            - project: project's uuid (FIXME, retrieve this information)

        Raises:
            ValueError: if the keys does not match (url and type) nor id.

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

        Note: Internal function for now, do not use outside of this module.

        Do not do anything fancy in case a person already exists.
        Please adapt code if more checks are needed.

        Args:
            person: dictionary with keys name and email.

        Returns:
            Id of the new person.

        """
        db = self.db

        return db.person_add(person)

    @db_transaction_generator
    def person_get(self, person, cur=None):
        """Return the persons identified by their ids.

        Args:
            person: array of ids.

        Returns:
            The array of persons corresponding of the ids.

        """
        db = self.db

        for person in db.person_get(person):
            yield dict(zip(db.person_get_cols, person))

    @db_transaction
    def origin_add(self, origins, cur=None):
        """Add origins to the storage

        Args:
            origins: list of dictionaries representing the individual origins,
                with the following keys:

                - type: the origin type ('git', 'svn', 'deb', ...)
                - url (bytes): the url the origin points to

        Returns:
            list: ids corresponding to the given origins

        """

        ret = []
        for origin in origins:
            ret.append(self.origin_add_one(origin, cur=cur))

        return ret

    @db_transaction
    def origin_add_one(self, origin, cur=None):
        """Add origin to the storage

        Args:
            origin: dictionary representing the individual origin to add. This
                dict has the following keys:

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
            entities (iterable): iterable of dictionaries with the following
                keys:

                - uuid (uuid): id of the entity
                - parent (uuid): id of the parent entity
                - name (str): name of the entity
                - type (str): type of entity (one of 'organization',
                  'group_of_entities', 'hosting', 'group_of_persons', 'person',
                  'project')
                - description (str, optional): description of the entity
                - homepage (str): url of the entity's homepage
                - active (bool): whether the entity is active
                - generated (bool): whether the entity was generated
                - lister_metadata (dict): lister-specific entity metadata
                - metadata (dict): other metadata for the entity
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
            entities (iterable): dictionaries containing the lister metadata to
               look for. Useful keys are 'lister', 'type', 'id', ...

        Yields:
            fetched entities with all their attributes. If no match was found,
            the returned entity is None.

        """

        db = self.db

        db.mktemp_entity_lister(cur)

        mapped_entities = []
        for i, entity in enumerate(entities):
            mapped_entity = {
                'id': i,
                'lister_metadata': entity,
            }
            mapped_entities.append(mapped_entity)

        db.copy_to(mapped_entities, 'tmp_entity_lister',
                   ['id', 'lister_metadata'], cur)

        cur.execute('''select id, %s
                       from swh_entity_from_tmp_entity_lister()
                       order by id''' %
                    ','.join(db.entity_cols))

        for id, *entity_vals in cur:
            fetched_entity = dict(zip(db.entity_cols, entity_vals))
            if fetched_entity['uuid']:
                yield fetched_entity
            else:
                yield {
                    'uuid': None,
                    'lister_metadata': entities[i],
                }

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
    def entity_get_one(self, uuid, cur=None):
        """Returns one entity using its uuid identifier.

        Args:
            uuid: entity's identifier

        Returns:
            the object corresponding to the given entity

        """
        db = self.db
        entity = db.entity_get_one(uuid, cur)
        if entity:
            return dict(zip(db.entity_cols, entity))
        else:
            return None

    @db_transaction
    def stat_counters(self, cur=None):
        """compute statistics about the number of tuples in various tables

        Returns:
            dict: a dictionary mapping textual labels (e.g., content) to
            integer values (e.g., the number of tuples in table content)

        """
        return {k: v for (k, v) in self.db.stat_counters()}

    @db_transaction_generator
    def content_mimetype_missing(self, mimetypes, cur=None):
        """List mimetypes missing from storage.

        Args:
            mimetypes (iterable): iterable of dict with keys:

                - id (bytes): sha1 identifier
                - tool_name (str): tool used to compute the results
                - tool_version (str): associated tool's version

        Returns:
            iterable: an iterable of missing id for the triplets id, tool_name,
            tool_version

        """
        db = self.db
        db.mktemp_content_mimetype_missing(cur)
        db.copy_to(mimetypes, 'tmp_content_mimetype_missing',
                   ['id', 'indexer_configuration_id'],
                   cur)
        for obj in db.content_mimetype_missing_from_temp(cur):
            yield obj[0]

    @db_transaction
    def content_mimetype_add(self, mimetypes, conflict_update=False, cur=None):
        """Add mimetypes not present in storage.

        Args:
            mimetypes (iterable): dictionaries with keys:

                - id (bytes): sha1 identifier
                - mimetype (bytes): raw content's mimetype
                - encoding (bytes): raw content's encoding
                - indexer_configuration_id (int): tool's id used to
                  compute the results
                - conflict_update: Flag to determine if we want to
                  overwrite (true) or skip duplicates (false, the default)

        """
        db = self.db
        db.mktemp_content_mimetype(cur)
        db.copy_to(mimetypes, 'tmp_content_mimetype',
                   ['id', 'mimetype', 'encoding', 'indexer_configuration_id'],
                   cur)
        db.content_mimetype_add_from_temp(conflict_update, cur)

    @db_transaction_generator
    def content_mimetype_get(self, ids, cur=None):
        db = self.db
        db.store_tmp_bytea(ids, cur)
        for c in db.content_mimetype_get_from_temp():
            yield converters.db_to_mimetype(
                dict(zip(db.content_mimetype_cols, c)))

    @db_transaction_generator
    def content_language_missing(self, languages, cur=None):
        """List languages missing from storage.

        Args:
            languages (iterable): dictionaries with keys:

                - id (bytes): sha1 identifier
                - tool_name (str): tool used to compute the results
                - tool_version (str): associated tool's version

        Returns:
            iterable: identifiers of missing languages

        """
        db = self.db
        db.mktemp_content_language_missing(cur)
        db.copy_to(languages, 'tmp_content_language_missing',
                   ['id', 'indexer_configuration_id'], cur)
        for obj in db.content_language_missing_from_temp(cur):
            yield obj[0]

    @db_transaction_generator
    def content_language_get(self, ids, cur=None):
        db = self.db
        db.store_tmp_bytea(ids, cur)
        for c in db.content_language_get_from_temp():
            yield converters.db_to_language(
                dict(zip(db.content_language_cols, c)))

    @db_transaction
    def content_language_add(self, languages, conflict_update=False, cur=None):
        """Add languages not present in storage.

        Args:
            languages (iterable): dictionaries with keys:

                - id: sha1
                - lang: bytes

            conflict_update: Flag to determine if we want to overwrite (true)
                or skip duplicates (false, the default)

        """
        db = self.db
        db.mktemp_content_language(cur)
        # empty language is mapped to 'unknown'
        db.copy_to(
            ({
                'id': l['id'],
                'lang': 'unknown' if not l['lang'] else l['lang'],
                'indexer_configuration_id': l['indexer_configuration_id'],
            } for l in languages),
            'tmp_content_language',
            ['id', 'lang', 'indexer_configuration_id'], cur)

        db.content_language_add_from_temp(conflict_update, cur)

    @db_transaction_generator
    def content_ctags_missing(self, ctags, cur=None):
        """List ctags missing from storage.

        Args:
            ctags (iterable): dicts with keys:

            - id (bytes): sha1 identifier
            - tool_name (str): tool name used
            - tool_version (str): associated version

        Returns:
            an iterable of missing id

        """
        db = self.db

        db.mktemp_content_ctags_missing(cur)
        db.copy_to(ctags,
                   tblname='tmp_content_ctags_missing',
                   columns=['id', 'indexer_configuration_id'],
                   cur=cur)
        for obj in db.content_ctags_missing_from_temp(cur):
            yield obj[0]

    @db_transaction_generator
    def content_ctags_get(self, ids, cur=None):
        """Retrieve ctags per id.

        Args:
            ids (iterable): sha1 checksums

        """
        db = self.db
        db.store_tmp_bytea(ids, cur)
        for c in db.content_ctags_get_from_temp():
            yield converters.db_to_ctags(dict(zip(db.content_ctags_cols, c)))

    @db_transaction
    def content_ctags_add(self, ctags, conflict_update=False, cur=None):
        """Add ctags not present in storage

        Args:
            ctags (iterable): dictionaries with keys:

                - id (bytes): sha1
                - ctags ([list): List of dictionary with keys: name, kind,
                  line, language

        """
        db = self.db

        def _convert_ctags(__ctags):
            """Convert ctags dict to list of ctags.

            """
            for ctags in __ctags:
                yield from converters.ctags_to_db(ctags)

        db.mktemp_content_ctags(cur)
        db.copy_to(list(_convert_ctags(ctags)),
                   tblname='tmp_content_ctags',
                   columns=['id', 'name', 'kind', 'line',
                            'lang', 'indexer_configuration_id'],
                   cur=cur)

        db.content_ctags_add_from_temp(conflict_update, cur)

    @db_transaction_generator
    def content_ctags_search(self, expression,
                             limit=10, last_sha1=None, cur=None):
        """Search through content's raw ctags symbols.

        Args:
            expression (str): Expression to search for
            limit (int): Number of rows to return (default to 10).
            last_sha1 (str): Offset from which retrieving data (default to '').

        Yields:
            rows of ctags including id, name, lang, kind, line, etc...

        """
        db = self.db

        for obj in db.content_ctags_search(expression, last_sha1, limit,
                                           cur=cur):
            yield converters.db_to_ctags(dict(zip(db.content_ctags_cols, obj)))

    @db_transaction_generator
    def content_fossology_license_get(self, ids, cur=None):
        """Retrieve licenses per id.

        Args:
            ids (iterable): sha1 checksums

        Yields:
            list: dictionaries with the following keys:

            - id (bytes)
            - licenses ([str]): associated licenses for that content

        """
        db = self.db
        db.store_tmp_bytea(ids, cur)

        for c in db.content_fossology_license_get_from_temp():
            license = dict(zip(db.content_fossology_license_cols, c))
            yield converters.db_to_fossology_license(license)

    @db_transaction
    def content_fossology_license_add(self, licenses,
                                      conflict_update=False, cur=None):
        """Add licenses not present in storage.

        Args:
            licenses (iterable): dictionaries with keys:

                - id: sha1
                - license ([bytes]): List of licenses associated to sha1
                - tool (str): nomossa

            conflict_update: Flag to determine if we want to overwrite (true)
                or skip duplicates (false, the default)

        Returns:
            list: content_license entries which failed due to unknown licenses

        """
        db = self.db

        # Then, we add the correct ones
        db.mktemp_content_fossology_license(cur)
        db.copy_to(
            ({
                'id': sha1['id'],
                'indexer_configuration_id': sha1['indexer_configuration_id'],
                'license': license,
              } for sha1 in licenses
                for license in sha1['licenses']),
            tblname='tmp_content_fossology_license',
            columns=['id', 'license', 'indexer_configuration_id'],
            cur=cur)
        db.content_fossology_license_add_from_temp(conflict_update, cur)

    @db_transaction_generator
    def content_metadata_missing(self, metadatas, cur=None):
        """List metadatas missing from storage.

        Args:
            metadatas (iterable): dictionaries with keys:

                - id (bytes): sha1 identifier
                - tool_name (str): tool used to compute the results
                - tool_version (str): associated tool's version

        Returns:
            iterable: missing ids

        """
        db = self.db
        db.mktemp_content_metadata_missing(cur)
        db.copy_to(metadatas, 'tmp_content_metadata_missing',
                   ['id', 'indexer_configuration_id'], cur)
        for obj in db.content_metadata_missing_from_temp(cur):
            yield obj[0]

    @db_transaction_generator
    def content_metadata_get(self, ids, cur=None):
        db = self.db
        db.store_tmp_bytea(ids, cur)
        for c in db.content_metadata_get_from_temp():
            yield converters.db_to_metadata(
                dict(zip(db.content_metadata_cols, c)))

    @db_transaction
    def content_metadata_add(self, metadatas, conflict_update=False, cur=None):
        """Add metadatas not present in storage.

        Args:
            metadatas (iterable): dictionaries with keys:

                - id: sha1
                - translated_metadata: bytes / jsonb ?

            conflict_update: Flag to determine if we want to overwrite (true)
                or skip duplicates (false, the default)

        """
        db = self.db
        db.mktemp_content_metadata(cur)
        # empty metadata is mapped to 'unknown'

        db.copy_to(metadatas, 'tmp_content_metadata',
                   ['id', 'translated_metadata', 'indexer_configuration_id'],
                   cur)
        db.content_metadata_add_from_temp(conflict_update, cur)

    @db_transaction_generator
    def revision_metadata_missing(self, metadatas, cur=None):
        """List metadatas missing from storage.

        Args:
            metadatas (iterable): dictionaries with keys:

               - id (bytes): sha1_git revision identifier
               - tool_name (str): tool used to compute the results
               - tool_version (str): associated tool's version

        Returns:
            iterable: missing ids

        """
        db = self.db
        db.mktemp_revision_metadata_missing(cur)
        db.copy_to(metadatas, 'tmp_revision_metadata_missing',
                   ['id', 'indexer_configuration_id'], cur)
        for obj in db.revision_metadata_missing_from_temp(cur):
            yield obj[0]

    @db_transaction_generator
    def revision_metadata_get(self, ids, cur=None):
        db = self.db
        db.store_tmp_bytea(ids, cur)
        for c in db.revision_metadata_get_from_temp():
            yield converters.db_to_metadata(
                dict(zip(db.revision_metadata_cols, c)))

    @db_transaction
    def revision_metadata_add(self, metadatas,
                              conflict_update=False, cur=None):
        """Add metadatas not present in storage.

        Args:
            metadatas (iterable): dictionaries with keys:

                - id: sha1_git of revision
                - translated_metadata: bytes / jsonb ?

            conflict_update: Flag to determine if we want to overwrite (true)
              or skip duplicates (false, the default)

        """
        db = self.db
        db.mktemp_revision_metadata(cur)
        # empty metadata is mapped to 'unknown'

        db.copy_to(metadatas, 'tmp_revision_metadata',
                   ['id', 'translated_metadata', 'indexer_configuration_id'],
                   cur)
        db.revision_metadata_add_from_temp(conflict_update, cur)

    @db_transaction
    def origin_metadata_add(self, origin_id, ts, provenance, metadata,
                            cur=None):
        """ Add an origin_metadata for the origin at ts with provenance and
        metadata.

        Args:
            origin_id: the origin's id for which the metadata is added
            ts: timestamp of the found metadata
            provenance (text): the tool and location where it was found
                        (ex:'deposit-hal')
            metadata (jsonb): the metadata retrieved at the time and location

        Returns:
            id (int): the origin_metadata unique id
        """
        if isinstance(ts, str):
            ts = dateutil.parser.parse(ts)

        return self.db.origin_metadata_add(origin_id, ts, provenance,
                                           metadata, cur)

    @db_transaction
    def origin_metadata_get(self, id, cur=None):
        """Return the origin_metadata entry for the unique id

        Returns:
            dict: the origin_metadata dictionary with the keys:

            - id: origin_metadata's id
            - origin_id: origin's id
            - discovery_date: timestamp of discovery
            - provenance (text): metadata's provenance
            - metadata (jsonb):

        """
        db = self.db

        om = db.origin_metadata_get(id, cur)

        if om:
            return dict(zip(self.db.origin_metadata_get_cols, om))
        return None

    @db_transaction_generator
    def origin_metadata_get_all(self, origin_id, cur=None):
        """Retrieve list of all origin_metadata entries for the origin_id

        Returns:
            list of dicts: the origin_metadata dictionary with the keys:

            - id: origin_metadata's id
            - origin_id: origin's id
            - discovery_date: timestamp of discovery
            - provenance (text): metadata's provenance
            - metadata (jsonb):

        """
        db = self.db
        for line in db.origin_metadata_get_all(origin_id, cur):
            data = dict(zip(self.db.origin_metadata_get_cols, line))
            yield data

    @db_transaction_generator
    def origin_metadata_get_by_provenance(self, origin_id, provenance,
                                          cur=None):
        """Retrieve list of origin_metadata entries for an origin and
        a specific provenance

        Returns:
            list of dicts: the origin_metadata dictionary with the keys:

            - id: origin_metadata's id
            - origin_id: origin's id
            - discovery_date: timestamp of discovery
            - provenance (text): metadata's provenance
            - metadata (jsonb):

        """
        db = self.db
        for line in db.origin_metadata_get_by_provenance(origin_id, provenance,
                                                         cur):
            data = dict(zip(self.db.origin_metadata_get_cols, line))
            yield data

    @db_transaction
    def indexer_configuration_get(self, tool, cur=None):
        db = self.db
        tool_conf = tool['tool_configuration']
        if isinstance(tool_conf, dict):
            tool_conf = json.dumps(tool_conf)
        idx = db.indexer_configuration_get(tool['tool_name'],
                                           tool['tool_version'],
                                           tool_conf)
        if not idx:
            return None
        return dict(zip(self.db.indexer_configuration_cols, idx))
