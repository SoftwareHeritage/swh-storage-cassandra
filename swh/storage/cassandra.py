# Copyright (C) 2019  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import functools
import json
import logging
import uuid
import warnings

from cassandra import WriteFailure, WriteTimeout, ReadFailure, ReadTimeout
from cassandra.cluster import Cluster
from cassandra.policies import RoundRobinPolicy, TokenAwarePolicy
import dateutil

from swh.model.model import (
    TimestampWithTimezone, Timestamp, Person, RevisionType, ObjectType,
    Revision, Release, Directory, DirectoryEntry,
)
from swh.objstorage import get_objstorage
from swh.objstorage.exc import ObjNotFoundError

from .journal_writer import get_journal_writer
from . import converters

# Max block size of contents to return
BULK_BLOCK_CONTENT_LEN_MAX = 10000


logger = logging.getLogger(__name__)


CREATE_TABLES_QUERIES = '''
CREATE OR REPLACE FUNCTION ascii_bins_count_sfunc (
    state tuple<int, map<ascii, int>>, -- (nb_none, map<target_type, nb>)
    bin_name ascii
)
CALLED ON NULL INPUT
RETURNS tuple<int, map<ascii, int>>
LANGUAGE java AS
$$
    if (bin_name == null) {
        state.setInt(0, state.getInt(0) + 1);
    }
    else {
        Map<String, Integer> counters = state.getMap(
            1, String.class, Integer.class);
        Integer nb = counters.get(bin_name);
        if (nb == null) {
            nb = 0;
        }
        counters.put(bin_name, nb + 1);
        state.setMap(1, counters, String.class, Integer.class);
    }
    return state;
$$
;

CREATE OR REPLACE AGGREGATE ascii_bins_count ( ascii )
SFUNC ascii_bins_count_sfunc
STYPE tuple<int, map<ascii, int>>
INITCOND (0, {})
;

CREATE TYPE IF NOT EXISTS microtimestamp (
    seconds             bigint,
    microseconds        int
);

CREATE TYPE IF NOT EXISTS microtimestamp_with_timezone (
    timestamp           frozen<microtimestamp>,
    offset              smallint,
    negative_utc        boolean
);

CREATE TYPE IF NOT EXISTS person (
    fullname    blob,
    name        blob,
    email       blob
);

CREATE TYPE IF NOT EXISTS dir_entry (
    target  blob,  -- id of target revision
    name    blob,  -- path name, relative to containing dir
    perms   int,   -- unix-like permissions
    type    ascii
);

CREATE TABLE IF NOT EXISTS content (
    sha1          blob,
    sha1_git      blob,
    sha256        blob,
    blake2s256    blob,
    length        bigint,
    ctime         timestamp,
        -- creation time, i.e. time of (first) injection into the storage
    status        ascii,
    PRIMARY KEY ((sha1, sha1_git, sha256, blake2s256))
);

CREATE TABLE IF NOT EXISTS revision (
    id                              blob PRIMARY KEY,
    date                            microtimestamp_with_timezone,
    committer_date                  microtimestamp_with_timezone,
    type                            ascii,
    directory                       blob,  -- source code "root" directory
    message                         blob,
    author                          person,
    committer                       person,
    parents                         frozen<list<blob>>,
    synthetic                       boolean,
        -- true iff revision has been created by Software Heritage
    metadata                        text
        -- extra metadata as JSON(tarball checksums,
        -- extra commit information, etc...)
);

CREATE TABLE IF NOT EXISTS release
(
    id                              blob PRIMARY KEY,
    target_type                     ascii,
    target                          blob,
    date                            microtimestamp_with_timezone,
    name                            blob,
    message                         blob,
    author                          person,
    synthetic                       boolean,
        -- true iff release has been created by Software Heritage
);

CREATE TABLE IF NOT EXISTS directory (
    id              blob PRIMARY KEY,
    entries_        frozen<list<dir_entry>>
);

CREATE TABLE IF NOT EXISTS snapshot (
    id              blob PRIMARY KEY,
);

-- For a given snapshot_id, branches are sorted by their name,
-- allowing easy pagination.
CREATE TABLE IF NOT EXISTS snapshot_branch (
    snapshot_id     blob,
    name            blob,
    target_type     ascii,
    target          blob,
    PRIMARY KEY ((snapshot_id), name)
);

CREATE TABLE IF NOT EXISTS origin_visit (
    origin          timeuuid,
    visit           bigint,
    date            timestamp,
    status          ascii,
    metadata        text,
    snapshot        blob,
    PRIMARY KEY ((origin), visit)
);


CREATE TABLE IF NOT EXISTS origin (
    id              timeuuid PRIMARY KEY,
    type            ascii,
    url             text,
    next_visit_id   int,
        -- We need integer visit ids for compatibility with the pgsql
        -- storage, so we're using lightweight transactions with this trick:
        -- https://stackoverflow.com/a/29391877/539465
);


CREATE INDEX IF NOT EXISTS origin_by_url ON origin (url);


CREATE TABLE IF NOT EXISTS tool_by_uuid (
    id              timeuuid PRIMARY KEY,
    name            ascii,
    version         ascii,
    configuration   blob,
);


CREATE TABLE IF NOT EXISTS tool (
    id              timeuuid,
    name            ascii,
    version         ascii,
    configuration   blob,
    PRIMARY KEY ((name, version, configuration))
)


CREATE TABLE IF NOT EXISTS object_count (
    partition_key   smallint,  -- Constant, must always be 0
    object_type     ascii,
    count           counter,
    PRIMARY KEY ((partition_key), object_type)
);
'''.split('\n\n')

CONTENT_INDEX_TEMPLATE = '''
CREATE TABLE IF NOT EXISTS content_by_{main_algo} (
    sha1          blob,
    sha1_git      blob,
    sha256        blob,
    blake2s256    blob,
    PRIMARY KEY (({main_algo}), {other_algos})
);'''

HASH_ALGORITHMS = ['sha1', 'sha1_git', 'sha256', 'blake2s256']

for main_algo in HASH_ALGORITHMS:
    CREATE_TABLES_QUERIES.append(CONTENT_INDEX_TEMPLATE.format(
        main_algo=main_algo,
        other_algos=', '.join(
            [algo for algo in HASH_ALGORITHMS if algo != main_algo])
    ))


def create_keyspace(hosts, keyspace, port=9042):
    cluster = Cluster(
        hosts, port=port,
        load_balancing_policy=RoundRobinPolicy())
    session = cluster.connect()
    session.execute('''CREATE KEYSPACE IF NOT EXISTS "%s"
                       WITH REPLICATION = {
                           'class' : 'SimpleStrategy',
                           'replication_factor' : 1
                       };
                    ''' % keyspace)
    session.execute('USE "%s"' % keyspace)
    for query in CREATE_TABLES_QUERIES:
        session.execute(query)


def revision_to_db(revision):
    metadata = revision.get('metadata')
    if metadata and 'extra_headers' in metadata:
        extra_headers = converters.git_headers_to_db(
            metadata['extra_headers'])
        revision = {
            **revision,
            'metadata': {
                **metadata,
                'extra_headers': extra_headers
            }
        }

    revision = Revision.from_dict(revision)
    revision.type = revision.type.value
    revision.metadata = json.dumps(revision.metadata)

    return revision


def revision_from_db(rev):
    rev.type = RevisionType(rev.type)
    metadata = json.loads(rev.metadata)
    if metadata and 'extra_headers' in metadata:
        extra_headers = converters.db_to_git_headers(
            metadata['extra_headers'])
        metadata['extra_headers'] = extra_headers
    rev.metadata = metadata

    return rev


def release_to_db(release):
    release = Release.from_dict(release)
    release.target_type = release.target_type.value
    return release


def release_from_db(release):
    release.target_type = ObjectType(release.target_type)
    return release


def prepared_statement(query):
    def decorator(f):
        @functools.wraps(f)
        def newf(self, *args, **kwargs):
            if f.__name__ not in self._prepared_statements:
                self._prepared_statements[f.__name__] = \
                    self._session.prepare(query)
            return f(self, *args, **kwargs,
                     statement=self._prepared_statements[f.__name__])
        return newf
    return decorator


def prepared_insert_statement(table_name, keys):
    return prepared_statement(
        'INSERT INTO %s (%s) VALUES (%s)' % (
            table_name,
            ', '.join(keys), ', '.join('?' for _ in keys),
        )
    )


class CassandraProxy:
    def __init__(self, hosts, keyspace, port):
        self._cluster = Cluster(
            hosts, port=port,
            load_balancing_policy=TokenAwarePolicy(RoundRobinPolicy()))
        self._session = self._cluster.connect(keyspace)
        self._cluster.register_user_type(
            keyspace, 'microtimestamp_with_timezone', TimestampWithTimezone)
        self._cluster.register_user_type(
            keyspace, 'microtimestamp', Timestamp)
        self._cluster.register_user_type(
            keyspace, 'person', Person)
        self._cluster.register_user_type(
            keyspace, 'dir_entry', DirectoryEntry)

        self._prepared_statements = {}

    MAX_RETRIES = 3

    def execute_and_retry(self, statement, args):
        for nb_retries in range(self.MAX_RETRIES):
            try:
                return self._session.execute(statement, args, timeout=100.)
            except (WriteFailure, WriteTimeout) as e:
                logger.error('Failed to write object to cassandra: %r', e)
                if nb_retries == self.MAX_RETRIES-1:
                    raise e
            except (ReadFailure, ReadTimeout) as e:
                logger.error('Failed to read object(s) to cassandra: %r', e)
                if nb_retries == self.MAX_RETRIES-1:
                    raise e

    @prepared_statement('UPDATE object_count SET count = count + ? '
                        'WHERE partition_key = 0 AND object_type = ?')
    def increment_counter(self, object_type, nb, *, statement):
        self.execute_and_retry(statement, [nb, object_type])

    def _add_one(self, statement, object_type, obj, keys):
        self.increment_counter(object_type, 1)
        return self.execute_and_retry(
            statement, [getattr(obj, key) for key in keys])

    _content_pk = ['sha1', 'sha1_git', 'sha256', 'blake2s256']
    _content_keys = [
        'sha1', 'sha1_git', 'sha256', 'blake2s256', 'length',
        'ctime', 'status']

    @prepared_insert_statement('content', _content_keys)
    def content_add_one(self, content, *, statement):
        self.execute_and_retry(
            statement, [content[key] for key in self._content_keys])
        self.increment_counter('content', 1)

    def content_index_add_one(self, main_algo, content):
        query = 'INSERT INTO content_by_{algo} ({cols}) VALUES ({values})' \
            .format(algo=main_algo, cols=', '.join(self._content_pk),
                    values=', '.join('%s' for _ in self._content_pk))
        self.execute_and_retry(
            query, [content[algo] for algo in self._content_pk])

    @prepared_statement('SELECT * FROM content WHERE ' +
                        ' AND '.join(map('%s = ?'.__mod__, HASH_ALGORITHMS)))
    def content_get_from_pk(self, content, *, statement):
        rows = list(self.execute_and_retry(
            statement, [content[algo] for algo in HASH_ALGORITHMS]))
        assert len(rows) <= 1
        if rows:
            return rows[0]

    def content_get_pks_from_single_hash(self, algo, hash_):
        assert algo in HASH_ALGORITHMS
        query = 'SELECT * FROM content_by_{algo} WHERE {algo} = %s'.format(
            algo=algo)
        return list(self.execute_and_retry(query, [hash_]))

    _revision_keys = [
        'id', 'date', 'committer_date', 'type', 'directory', 'message',
        'author', 'committer', 'parents',
        'synthetic', 'metadata']

    @prepared_insert_statement('revision', _revision_keys)
    def revision_add_one(self, revision, *, statement):
        self._add_one(statement, 'revision', revision, self._revision_keys)

    _release_keys = [
        'id', 'target', 'target_type', 'date', 'name', 'message', 'author',
        'synthetic']

    @prepared_insert_statement('release', _release_keys)
    def release_add_one(self, release, *, statement):
        self._add_one(statement, 'release', release, self._release_keys)

    _directory_keys = ['id', 'entries_']
    _directory_attributes = ['id', 'entries']

    @prepared_insert_statement('directory', _directory_keys)
    def directory_add_one(self, directory, *, statement):
        self._add_one(
            statement, 'directory', directory, self._directory_attributes)

    _snapshot_keys = ['id']

    @prepared_statement('SELECT id FROM snapshot WHERE id=? LIMIT 1')
    def snapshot_exists(self, snapshot_id, *, statement):
        return len(list(self.execute_and_retry(statement, [snapshot_id]))) > 0

    @prepared_insert_statement('snapshot', _snapshot_keys)
    def snapshot_add_one(self, snapshot_id, *, statement):
        self.execute_and_retry(statement, [snapshot_id])
        self.increment_counter('snapshot', 1)

    _snapshot_branch_keys = ['snapshot_id', 'name', 'target_type', 'target']

    @prepared_insert_statement('snapshot_branch', _snapshot_branch_keys)
    def snapshot_branch_add_one(self, branch, *, statement):
        return self.execute_and_retry(
            statement, [branch[key] for key in self._snapshot_branch_keys])

    @prepared_statement('SELECT ascii_bins_count(target_type) AS counts '
                        'FROM snapshot_branch '
                        'WHERE snapshot_id = ? ')
    def snapshot_count_branches(self, snapshot_id, *, statement):
        return self.execute_and_retry(statement, [snapshot_id])

    @prepared_statement('SELECT * FROM snapshot_branch '
                        'WHERE snapshot_id = ? AND name >= ?'
                        'LIMIT ?')
    def snapshot_branch_get(self, snapshot_id, from_, limit, *, statement):
        return self.execute_and_retry(statement, [snapshot_id, from_, limit])

    @prepared_statement('INSERT INTO origin (id, type, url, next_visit_id) '
                        'VALUES (?, ?, ?, 1) IF NOT EXISTS')
    def origin_add_one(self, origin, *, statement):
        id_ = uuid.uuid1()
        self.execute_and_retry(
            statement, [id_, origin['type'], origin['url']])
        self.increment_counter('origin', 1)
        return id_

    @prepared_statement('SELECT * FROM origin WHERE id = ?')
    def origin_get_by_id(self, id_, *, statement):
        return self.execute_and_retry(statement, [id_])

    @prepared_statement('SELECT * FROM origin WHERE url = ? AND type = ? '
                        'ALLOW FILTERING')
    def origin_get_by_type_and_url(self, type_, url, *, statement):
        return self.execute_and_retry(statement, [url, type_])

    @prepared_statement('SELECT next_visit_id FROM origin WHERE id = ?')
    def _origin_get_next_visit_id(self, origin_id, *, statement):
        rows = list(self.execute_and_retry(statement, [origin_id]))
        assert len(rows) == 1  # TODO: error handling
        return rows[0].next_visit_id

    @prepared_statement('UPDATE origin SET next_visit_id=? '
                        'WHERE id = ? IF next_visit_id=?')
    def origin_generate_unique_visit_id(self, origin_id, *, statement):
        origin_id = uuid.UUID(origin_id)
        next_id = self._origin_get_next_visit_id(origin_id)
        while True:
            res = list(self.execute_and_retry(
                statement, [next_id+1, origin_id, next_id]))
            assert len(res) == 1
            if res[0].applied:
                # No data race
                return next_id
            else:
                # Someone else updated it before we did, let's try again
                next_id = res[0].next_visit_id
                # TODO: abort after too many attempts

        return next_id

    _origin_visit_keys = [
        'origin', 'visit', 'date', 'status', 'metadata', 'snapshot']
    _origin_visit_update_keys = [
        'date', 'status', 'metadata', 'snapshot']

    @prepared_insert_statement('origin_visit', _origin_visit_keys)
    def origin_visit_add_one(self, visit, *, statement):
        self.execute_and_retry(
            statement, [visit[key] for key in self._origin_visit_keys])
        self.increment_counter('origin_visit', 1)

    @prepared_statement(
        'UPDATE origin_visit SET ' +
        ', '.join('%s = ?' % key for key in _origin_visit_update_keys) +
        ' WHERE origin = ? AND visit = ?')
    def origin_visit_upsert(self, visit, *, statement):
        self.execute_and_retry(
            statement,
            [visit[key] for key in self._origin_visit_update_keys]
            + [uuid.UUID(visit['origin']), visit['visit']])
        # TODO: check if there is already one
        self.increment_counter('origin_visit', 1)

    @prepared_statement('SELECT * FROM origin_visit '
                        'WHERE origin = ? AND visit = ?')
    def origin_visit_get_one(self, origin_id, visit_id, *, statement):
        # TODO: error handling
        return self.execute_and_retry(
            statement, [uuid.UUID(origin_id), visit_id])[0]

    @prepared_statement('SELECT * FROM origin_visit WHERE origin = ?')
    def origin_visit_get_latest_with_snap(
            self, origin, allowed_statuses, *, statement):
        # TODO: do the ordering and filtering in Cassandra
        rows = list(self.execute_and_retry(statement, [uuid.UUID(origin)]))

        rows.sort(key=lambda row: (row.date, row.visit), reverse=True)

        for row in rows:
            has_snapshot = row.snapshot is not None
            has_allowed_status = \
                allowed_statuses is None or row.status in allowed_statuses
            if has_snapshot and has_allowed_status:
                if self.snapshot_exists(row.snapshot):
                    return row

    _tool_keys = ['id', 'name', 'version', 'configuration']

    @prepared_insert_statement('tool_by_uuid', _tool_keys)
    def tool_by_uuid_add_one(self, tool, *, statement):
        self.execute_and_retry(
            statement, [tool[key] for key in self._tool_keys])

    @prepared_insert_statement('tool', _tool_keys)
    def tool_add_one(self, tool, *, statement):
        self.execute_and_retry(
            statement, [tool[key] for key in self._tool_keys])
        self.increment_counter('tool', 1)

    @prepared_statement('SELECT id FROM tool '
                        'WHERE name = ? AND version = ? '
                        'AND configuration = ?')
    def tool_get_one_uuid(self, name, version, configuration, *, statement):
        rows = list(self.execute_and_retry(
            statement, [name, version, configuration]))
        if rows:
            assert len(rows) == 1
            return rows[0].id


class CassandraStorage:
    def __init__(self, hosts, keyspace, objstorage,
                 port=9042, journal_writer=None):
        self._proxy = CassandraProxy(hosts, keyspace, port)

        self.objstorage = get_objstorage(**objstorage)

        if journal_writer:
            self.journal_writer = get_journal_writer(**journal_writer)
        else:
            self.journal_writer = None

    def check_config(self, check_write=False):
        self._proxy.execute_and_retry(
            'SELECT uuid() FROM revision LIMIT 1;', [])

        return True

    def _missing(self, table, ids):
        res = self._proxy.execute_and_retry(
            'SELECT id FROM %s WHERE id IN (%s)' %
            (table, ', '.join('%s' for _ in ids)),
            ids
        )
        found_ids = {id_ for (id_,) in res}
        return [id_ for id_ in ids if id_ not in found_ids]

    def _content_add(self, contents, with_data):
        if self.journal_writer:
            for content in contents:
                if 'data' in content:
                    content = content.copy()
                    del content['data']
                self.journal_writer.write_addition('content', content)

        count_contents = 0
        count_content_added = 0
        count_content_bytes_added = 0

        for content in contents:
            if self._proxy.content_get_from_pk(content):
                # We already have it
                continue

            for algo in HASH_ALGORITHMS:
                self._proxy.content_index_add_one(algo, content)

            self._proxy.content_add_one(content)

            # Note that we check for collisions *after* inserting. This
            # differs significantly from the pgsql storage, but checking
            # before insertion does not provide any guarantee in case
            # another thread inserts the colliding hash at the same time.
            #
            # The proper way to do it would probably be a BATCH, but this
            # would be inefficient because of the number of partitions we
            # need to affect (len(HASH_ALGORITHMS)+1, which is currently 5)
            for algo in {'sha1', 'sha1_git'}:
                pks = self._proxy.content_get_pks_from_single_hash(
                    algo, content[algo])
                if len(pks) > 1:
                    # There are more than the one we just inserted.
                    from . import HashCollision
                    raise HashCollision(algo, content[algo], pks)

            count_contents += 1
            if content['status'] == 'visible':
                count_content_added += 1
                if with_data:
                    content_data = content['data']
                    count_content_bytes_added += len(content_data)
                    self.objstorage.add(content_data, content['sha1'])

        summary = {
            'content:add': count_content_added,
            'skipped_content:add': count_contents - count_content_added,
        }

        if with_data:
            summary['content:add:bytes'] = count_content_bytes_added

        return summary

    def content_add(self, contents):
        contents = [dict(c.items()) for c in contents]  # semi-shallow copy
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        for item in contents:
            item['ctime'] = now
        return self._content_add(contents, with_data=True)

    def content_add_metadata(self, contents):
        return self._content_add(contents, with_data=False)

    def content_get(self, ids):
        if len(ids) > BULK_BLOCK_CONTENT_LEN_MAX:
            raise ValueError(
                "Sending at most %s contents." % BULK_BLOCK_CONTENT_LEN_MAX)
        for obj_id in ids:
            try:
                data = self.objstorage.get(obj_id)
            except ObjNotFoundError:
                yield None
                continue

            yield {'sha1': obj_id, 'data': data}

    def content_get_metadata(self, sha1s):
        for sha1 in sha1s:
            pks = self._proxy.content_get_pks_from_single_hash('sha1', sha1)
            if pks:
                # TODO: what to do if there are more than one?
                pk = pks[0]
                res = self._proxy.content_get_from_pk(pk._asdict())
                # Rows in 'content' are always inserted before corresponding
                # rows in 'content_by_*', there should always be one.
                assert res is not None
                content_metadata = res._asdict()
                content_metadata.pop('ctime')
                yield content_metadata
            else:
                # FIXME: should really be None
                yield {
                    'sha1': sha1,
                    'sha1_git': None,
                    'sha256': None,
                    'blake2s256': None,
                    'length': None,
                    'status': None,
                }

    def content_find(self, content):
        filter_algos = list(set(content).intersection(HASH_ALGORITHMS))
        if not filter_algos:
            raise ValueError('content keys must contain at least one of: '
                             '%s' % ', '.join(sorted(HASH_ALGORITHMS)))
        # Find all contents with one of the hash that matches
        found_pks = self._proxy.content_get_pks_from_single_hash(
            filter_algos[0], content[filter_algos[0]])
        found_pks = [pk._asdict() for pk in found_pks]

        # Filter with the other hashes.
        for algo in filter_algos[1:]:
            found_pks = [pk for pk in found_pks if pk[algo] == content[algo]]

        results = []
        for pk in found_pks:
            res = self._proxy.content_get_from_pk(pk)
            # Rows in 'content' are always inserted before corresponding
            # rows in 'content_by_*', there should always be one.
            assert res is not None
            results.append({
                **res._asdict(),
                'ctime': res.ctime.replace(tzinfo=datetime.timezone.utc)
            })
        return results

    def content_missing(self, contents, key_hash='sha1'):
        for content in contents:
            res = self.content_find(content)
            if not res:
                yield content[key_hash]
            if any(c['status'] == 'missing' for c in res):
                yield content[key_hash]

    def content_missing_per_sha1(self, contents):
        return self.content_missing([{'sha1': c for c in contents}])

    def directory_add(self, directories):
        if self.journal_writer:
            self.journal_writer.write_additions('directory', directories)

        missing = self.directory_missing([dir_['id'] for dir_ in directories])

        for directory in directories:
            if directory['id'] in missing:
                self._proxy.directory_add_one(
                    Directory.from_dict(directory))

        return {'directory:add': len(missing)}

    def directory_missing(self, directory_ids):
        return self._missing('directory', directory_ids)

    def _join_dentry_to_content(self, dentry):
        keys = (
            'status',
            'sha1',
            'sha1_git',
            'sha256',
            'length',
        )
        ret = dict.fromkeys(keys)
        ret.update(dentry.to_dict())
        if ret['type'] == 'file':
            content = self.content_find({'sha1_git': ret['target']})
            if content:
                for key in keys:
                    ret[key] = content[key]
        return ret

    def _directory_ls(self, directory_id, recursive, prefix=b''):
        rows = list(self._proxy.execute_and_retry(
            'SELECT * FROM directory WHERE id = %s',
            (directory_id,)))
        if not rows:
            return
        assert len(rows) == 1

        dir_ = rows[0]._asdict()
        dir_['entries'] = dir_.pop('entries_')
        dir_ = Directory(**dir_)
        for entry in dir_.entries:
            ret = self._join_dentry_to_content(entry)
            ret['name'] = prefix + ret['name']
            ret['dir_id'] = directory_id
            yield ret
            if recursive and ret['type'] == 'dir':
                yield from self._directory_ls(
                    ret['target'], True, prefix + ret['name'] + b'/')

    def directory_entry_get_by_path(self, directory, paths):
        if not paths:
            return

        contents = list(self.directory_ls(directory))

        if not contents:
            return

        def _get_entry(entries, name):
            for entry in entries:
                if entry['name'] == name:
                    return entry

        first_item = _get_entry(contents, paths[0])

        if len(paths) == 1:
            return first_item

        if not first_item or first_item['type'] != 'dir':
            return

        return self.directory_entry_get_by_path(
                first_item['target'], paths[1:])

    def directory_ls(self, directory_id, recursive=False):
        yield from self._directory_ls(directory_id, recursive)

    def revision_add(self, revisions, check_missing=True):
        if self.journal_writer:
            self.journal_writer.write_additions('revision', revisions)

        if check_missing:
            missing = self.revision_missing([rev['id'] for rev in revisions])

        for revision in revisions:
            if check_missing and revision['id'] not in missing:
                continue

            revision = revision_to_db(revision)

            if revision:
                self._proxy.revision_add_one(revision)

        if check_missing:
            return {'revision:add': len(missing)}
        else:
            return {'revision:add': len(revisions)}

    def revision_missing(self, revision_ids):
        return self._missing('revision', revision_ids)

    def revision_get(self, revision_ids):
        rows = self._proxy.execute_and_retry(
            'SELECT * FROM revision WHERE id IN ({})'.format(
                ', '.join('%s' for _ in revision_ids)),
            revision_ids)
        revs = {}
        for row in rows:
            rev = Revision(**row._asdict())
            rev = revision_from_db(rev)
            revs[rev.id] = rev.to_dict()

        for rev_id in revision_ids:
            yield revs.get(rev_id)

    def _get_parent_revs(self, rev_ids, seen, limit, short):
        if limit and len(seen) >= limit:
            return
        rev_ids = [id_ for id_ in rev_ids if id_ not in seen]
        if not rev_ids:
            return
        seen |= set(rev_ids)
        rows = self._proxy.execute_and_retry(
            'SELECT {} FROM revision WHERE id IN ({})'.format(
                'id, parents' if short else '*',
                ', '.join('%s' for _ in rev_ids)),
            rev_ids)
        for row in rows:
            if short:
                (id_, parents) = row
                yield (id_, parents)
            else:
                rev = revision_from_db(Revision(**row._asdict()))
                parents = rev.parents
                yield rev.to_dict()
            yield from self._get_parent_revs(parents, seen, limit, short)

    def revision_log(self, revision_ids, limit=None):
        """Fetch revision entry from the given root revisions.

        Args:
            revisions: array of root revision to lookup
            limit: limitation on the output result. Default to None.

        Yields:
            List of revision log from such revisions root.

        """
        seen = set()
        yield from self._get_parent_revs(revision_ids, seen, limit, False)

    def revision_shortlog(self, revisions, limit=None):
        """Fetch the shortlog for the given revisions

        Args:
            revisions: list of root revisions to lookup
            limit: depth limitation for the output

        Yields:
            a list of (id, parents) tuples.

        """
        seen = set()
        yield from self._get_parent_revs(revisions, seen, limit, True)

    def release_add(self, releases):
        if self.journal_writer:
            self.journal_writer.write_additions('release', releases)

        missing = self.release_missing([rel['id'] for rel in releases])

        for release in releases:
            release = release_to_db(release)

            if release.id not in missing:
                continue

            if release:
                self._proxy.release_add_one(release)

        return {'release:add': len(missing)}

    def release_missing(self, release_ids):
        return self._missing('release', release_ids)

    def release_get(self, release_ids):
        rows = self._proxy.execute_and_retry(
            'SELECT * FROM release WHERE id IN ({})'.format(
                ', '.join('%s' for _ in release_ids)),
            release_ids)
        rels = {}
        for row in rows:
            release = Release(**row._asdict())
            release = release_from_db(release)
            rels[row.id] = release.to_dict()

        for rel_id in release_ids:
            yield rels.get(rel_id)

    def snapshot_add(self, snapshots, legacy_arg1=None, legacy_arg2=None):
        if legacy_arg1:
            assert legacy_arg2
            (origin, visit, snapshots) = \
                (snapshots, legacy_arg1, [legacy_arg2])
        else:
            origin = visit = None

        count = 0
        for snapshot in snapshots:
            if self._proxy.snapshot_exists(snapshot['id']):
                continue

            count += 1

            if self.journal_writer:
                self.journal_writer.write_addition('snapshot', snapshot)

            for (branch_name, branch) in snapshot['branches'].items():
                if branch is None:
                    branch = {'target_type': None, 'target': None}
                self._proxy.snapshot_branch_add_one({
                    'snapshot_id': snapshot['id'],
                    'name': branch_name,
                    'target_type': branch['target_type'],
                    'target': branch['target'],
                })

            # Add the snapshot *after* adding all the branches, so someone
            # calling snapshot_get_branch in the meantime won't end up
            # with half the branches.
            self._proxy.snapshot_add_one(snapshot['id'])

        if origin:
            # Legacy API, there can be only one snapshot
            self.origin_visit_update(
                origin, visit, snapshot=snapshots[0]['id'])

        return {'snapshot:add': count}

    def snapshot_get(self, snapshot_id):
        return self.snapshot_get_branches(snapshot_id)

    def snapshot_get_by_origin_visit(self, origin, visit):
        try:
            visit = self._proxy.origin_visit_get_one(origin, visit)
        except IndexError:
            return None

        return self.snapshot_get(visit.snapshot)

    def snapshot_get_latest(self, origin, allowed_statuses=None):
        visit = self._proxy.origin_visit_get_latest_with_snap(
            origin, allowed_statuses)

        if visit:
            assert visit.snapshot
            return self.snapshot_get_branches(visit.snapshot)

    def snapshot_count_branches(self, snapshot_id):
        if not self._proxy.snapshot_exists(snapshot_id):
            # Makes sure we don't fetch branches for a snapshot that is
            # being added.
            return None
        rows = list(self._proxy.snapshot_count_branches(snapshot_id))
        assert len(rows) == 1
        (nb_none, counts) = rows[0].counts
        counts = dict(counts)
        if nb_none:
            counts[None] = nb_none
        return counts

    def snapshot_get_branches(self, snapshot_id, branches_from=b'',
                              branches_count=1000, target_types=None):
        if not self._proxy.snapshot_exists(snapshot_id):
            # Makes sure we don't fetch branches for a snapshot that is
            # being added.
            return None

        branches = list(self._proxy.snapshot_branch_get(
            snapshot_id, branches_from, branches_count+1))

        if len(branches) > branches_count:
            last_branch = branches.pop(-1).name
        else:
            last_branch = None

        branches = {
            branch.name: {
                'target': branch.target,
                'target_type': branch.target_type,
            } if branch.target else None
            for branch in branches
        }

        if target_types:
            branches = {name: branch
                        for (name, branch) in branches.items()
                        if branch is not None
                        and branch['target_type'] in target_types}

        return {
            'id': snapshot_id,
            'branches': branches,
            'next_branch': last_branch,
        }

    OBJECT_FIND_TYPES = ('revision', 'release', 'content', 'directory')
    # Mind the order, revision is the most likely one for a given ID,
    # so we check revisions first.

    def object_find_by_sha1_git(self, ids):
        results = {id_: [] for id_ in ids}
        missing_ids = set(ids)

        for object_type in self.OBJECT_FIND_TYPES:
            table = object_type
            col = 'id'
            if object_type == 'content':
                table = 'content_by_sha1_git'
                col = 'sha1_git'
            rows = self._proxy.execute_and_retry(
                'SELECT {col} AS id FROM {table} WHERE {col} IN ({values})'
                .format(
                    table=table, col=col,
                    values=', '.join('%s' for _ in missing_ids)),
                missing_ids)
            for row in rows:
                results[row.id].append({
                    'sha1_git': row.id,
                    'type': object_type,
                })
                missing_ids.remove(row.id)

            if not missing_ids:
                # We found everything, skipping the next queries.
                break

        return results

    def origin_get(self, origins):
        if isinstance(origins, dict):
            # Old API
            return_single = True
            origins = [origins]
        else:
            return_single = False

        # Sanity check to be error-compatible with the pgsql backend
        if any('id' in origin for origin in origins) \
                and not all('id' in origin for origin in origins):
            raise ValueError(
                'Either all origins or none at all should have an "id".')
        if any('type' in origin and 'url' in origin for origin in origins) \
                and not all('type' in origin and 'url' in origin
                            for origin in origins):
            raise ValueError(
                'Either all origins or none at all should have a '
                '"type" and an "url".')

        results = [self.origin_get_one(origin) for origin in origins]

        if return_single:
            assert len(results) == 1
            return results[0]
        else:
            return results

    def origin_get_one(self, origin):
        if 'id' in origin:
            rows = self._proxy.origin_get_by_id(uuid.UUID(origin['id']))
        elif 'type' in origin and 'url' in origin:
            rows = self._proxy.origin_get_by_type_and_url(
                origin['type'], origin['url'])
        else:
            raise ValueError(
                'Origin must have either id or (type and url).')

        rows = list(rows)
        if rows:
            assert len(rows) == 1
            result = rows[0]._asdict()
            return {
                'id': str(result['id']),
                'url': result['url'],
                'type': result['type'],
            }
        else:
            return None

    def origin_add(self, origins):
        if any('id' in origin for origin in origins):
            raise ValueError('Origins must not already have an id.')
        results = []
        for origin in origins:
            origin = origin.copy()
            origin['id'] = str(self.origin_add_one(origin))
            results.append(origin)
        return results

    def origin_add_one(self, origin):
        assert 'id' not in origin

        known_origin = self.origin_get_one(origin)

        if known_origin:
            origin_id = known_origin['id']
        else:
            if self.journal_writer:
                self.journal_writer.write_addition('origin', origin)

            origin_id = str(self._proxy.origin_add_one(origin))

        return origin_id

    def origin_visit_add(self, origin, date=None, *, ts=None):
        if ts is None:
            if date is None:
                raise TypeError('origin_visit_add expected 2 arguments.')
        else:
            assert date is None
            warnings.warn("argument 'ts' of origin_visit_add was renamed "
                          "to 'date' in v0.0.109.",
                          DeprecationWarning)
            date = ts

        origin_id = origin  # TODO: rename the argument

        if isinstance(date, str):
            date = dateutil.parser.parse(date)

        origin = self.origin_get_one({'id': origin_id})

        if not origin:
            return None

        visit_id = self._proxy.origin_generate_unique_visit_id(origin_id)

        visit = {
            'origin': uuid.UUID(origin_id),
            'date': date,
            'status': 'ongoing',
            'snapshot': None,
            'metadata': None,
            'visit': visit_id
        }

        if self.journal_writer:
            origin = self.origin_get_one({'id': origin_id})
            del origin['id']
            self.journal_writer.write_addition('origin_visit', {
                **visit, 'origin': origin})

        self._proxy.origin_visit_add_one(visit)

        return {
                'origin': origin_id,
                'visit': visit_id,
            }

    def origin_visit_update(self, origin, visit_id, status=None,
                            metadata=None, snapshot=None):
        origin_id = origin  # TODO: rename the argument

        try:
            visit = self._proxy.origin_visit_get_one(origin_id, visit_id) \
                ._asdict()
        except IndexError:
            raise ValueError('This origin visit does not exist.')

        if self.journal_writer:
            origin = self.origin_get_one({'id': origin_id})
            del origin['id']
            self.journal_writer.write_update('origin_visit', {
                'origin': origin, 'visit': visit_id,
                'status': status or visit['status'],
                'date': visit['date'].replace(tzinfo=datetime.timezone.utc),
                'metadata': metadata or visit['metadata'],
                'snapshot': snapshot or visit['snapshot']})

        set_parts = []
        args = []
        if status:
            set_parts.append('status = %s')
            args.append(status)
        if metadata:
            set_parts.append('metadata = %s')
            args.append(json.dumps(metadata))
        if snapshot:
            set_parts.append('snapshot = %s')
            args.append(snapshot)

        if not set_parts:
            return

        query = ('UPDATE origin_visit SET ' + ', '.join(set_parts) +
                 ' WHERE origin = %s AND visit = %s')
        self._proxy.execute_and_retry(
            query, args + [uuid.UUID(origin_id), visit_id])

    def origin_visit_upsert(self, visits):
        if self.journal_writer:
            for visit in visits:
                visit = visit.copy()
                visit['origin'] = self.origin_get([{'id': visit['origin']}])[0]
                del visit['origin']['id']
                self.journal_writer.write_addition('origin_visit', visit)

        for visit in visits:
            visit = visit.copy()
            if isinstance(visit['date'], str):
                visit['date'] = dateutil.parser.parse(visit['date'])
            if visit['metadata']:
                visit['metadata'] = json.dumps(visit['metadata'])
            self._proxy.origin_visit_upsert(visit)

    @staticmethod
    def _format_origin_visit_row(visit):
        return {
            **visit._asdict(),
            'origin': str(visit.origin),
            'date': visit.date.replace(tzinfo=datetime.timezone.utc),
            'metadata': (json.loads(visit.metadata)
                         if visit.metadata else None),
        }

    def origin_visit_get(self, origin, last_visit=None, limit=None):
        query_parts = ['SELECT * FROM origin_visit WHERE', 'origin=%s']
        args = [uuid.UUID(origin)]

        if last_visit:
            query_parts.append('AND visit > %s')
            args.append(last_visit)

        # FIXME: is this a noop? (given the table def, it's already ordered)
        query_parts.append('ORDER BY visit ASC')

        if limit:
            query_parts.append('LIMIT %s')
            args.append(limit)

        query_parts.append('ALLOW FILTERING')

        rows = self._proxy.execute_and_retry(' '.join(query_parts), args)

        yield from map(self._format_origin_visit_row, rows)

    def origin_visit_get_by(self, origin, visit):
        try:
            return self._format_origin_visit_row(
                self._proxy.origin_visit_get_one(origin, visit))
        except IndexError:
            return None

    def tool_add(self, tools):
        inserted = []
        for tool in tools:
            tool = tool.copy()
            tool_json = tool.copy()
            tool_json['configuration'] = json.dumps(
                tool['configuration'], sort_keys=True).encode()
            id_ = self._proxy.tool_get_one_uuid(**tool_json)
            if not id_:
                id_ = uuid.uuid1()
                tool_json['id'] = id_
                self._proxy.tool_by_uuid_add_one(tool_json)
                self._proxy.tool_add_one(tool_json)
            tool['id'] = id_
            inserted.append(tool)
        return inserted

    def tool_get(self, tool):
        id_ = self._proxy.tool_get_one_uuid(
            tool['name'], tool['version'],
            json.dumps(tool['configuration'], sort_keys=True).encode())
        if id_:
            tool = tool.copy()
            tool['id'] = id_
            return tool
        else:
            return None

    def stat_counters(self):
        rows = self._proxy.execute_and_retry(
            'SELECT object_type, count FROM object_count '
            'WHERE partition_key=0', [])
        keys = (
            'content', 'directory', 'origin', 'origin_visit',
            'release', 'revision', 'skipped_content', 'snapshot')
        stats = {key: 0 for key in keys}
        stats.update({row.object_type: row.count for row in rows})
        return stats

    def refresh_stat_counters(self):
        pass
