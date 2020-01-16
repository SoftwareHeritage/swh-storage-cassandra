# Copyright (C) 2019  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import functools
import hashlib
import json
import logging
import random
import re
from typing import (
    Any, Callable, Dict, Generator, Iterable, List, Optional, TypeVar
)
import uuid
import warnings

import attr
from cassandra import WriteFailure, WriteTimeout, ReadFailure, ReadTimeout
from cassandra.cluster import (
    Cluster, EXEC_PROFILE_DEFAULT, ExecutionProfile, ResultSet)
from cassandra.policies import DCAwareRoundRobinPolicy, TokenAwarePolicy
from cassandra.query import PreparedStatement
import dateutil

from swh.model.model import (
    TimestampWithTimezone, Timestamp, Person, RevisionType, ObjectType,
    Revision, Release, Directory, DirectoryEntry, Content, OriginVisit,
    Sha1Git
)
from swh.objstorage import get_objstorage
from swh.objstorage.exc import ObjNotFoundError
try:
    from swh.journal.writer import get_journal_writer
except ImportError:
    get_journal_writer = None  # type: ignore
    # mypy limitation, see https://github.com/python/mypy/issues/1153

from . import converters


Row = tuple


# Max block size of contents to return
BULK_BLOCK_CONTENT_LEN_MAX = 10000


TOKEN_BEGIN = -(2**63)
'''Minimum value returned by the CQL function token()'''
TOKEN_END = 2**63-1
'''Maximum value returned by the CQL function token()'''


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
    synthetic                       boolean,
        -- true iff revision has been created by Software Heritage
    metadata                        text
        -- extra metadata as JSON(tarball checksums,
        -- extra commit information, etc...)
);

CREATE TABLE IF NOT EXISTS revision_parent (
    id                     blob,
    parent_rank                     int,
        -- parent position in merge commits, 0-based
    parent_id                       blob,
    PRIMARY KEY ((id), parent_rank)
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
);

CREATE TABLE IF NOT EXISTS directory_entry (
    directory_id    blob,
    name            blob,  -- path name, relative to containing dir
    target          blob,
    perms           int,   -- unix-like permissions
    type            ascii, -- target type
    PRIMARY KEY ((directory_id), name)
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
    origin          text,
    visit           bigint,
    date            timestamp,
    type            text,
    status          ascii,
    metadata        text,
    snapshot        blob,
    PRIMARY KEY ((origin), visit)
);


CREATE TABLE IF NOT EXISTS origin (
    sha1            blob PRIMARY KEY,
    url             text,
    type            text,
    next_visit_id   int,
        -- We need integer visit ids for compatibility with the pgsql
        -- storage, so we're using lightweight transactions with this trick:
        -- https://stackoverflow.com/a/29391877/539465
);


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


execution_profiles = {
    EXEC_PROFILE_DEFAULT: ExecutionProfile(
        load_balancing_policy=TokenAwarePolicy(DCAwareRoundRobinPolicy())),
}


def hash_url(url):
    return hashlib.sha1(url.encode('ascii')).digest()


def now():
    return datetime.datetime.now(tz=datetime.timezone.utc)


def create_keyspace(hosts: List[str], keyspace: str, port: int = 9042):
    cluster = Cluster(
        hosts, port=port, execution_profiles=execution_profiles)
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


def revision_to_db(revision: Dict[str, Any]) -> Revision:
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

    rev = Revision.from_dict(revision)
    rev = attr.evolve(
        rev,
        type=rev.type.value,
        metadata=json.dumps(rev.metadata),
    )

    return rev


def revision_from_db(revision) -> Revision:
    metadata = json.loads(revision.metadata)
    if metadata and 'extra_headers' in metadata:
        extra_headers = converters.db_to_git_headers(
            metadata['extra_headers'])
        metadata['extra_headers'] = extra_headers
    rev = attr.evolve(
        revision,
        type=RevisionType(revision.type),
        metadata=metadata,
    )

    return rev


def release_to_db(release: Dict[str, Any]) -> Release:
    rel = Release.from_dict(release)
    rel = attr.evolve(
        rel,
        target_type=rel.target_type.value,
    )
    return rel


def release_from_db(release: Release) -> Release:
    release = attr.evolve(
        release,
        target_type=ObjectType(release.target_type),
    )
    return release


T = TypeVar('T')


def prepared_statement(
        query: str) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Returns a decorator usable on methods of CassandraProxy, to
    inject them with a 'statement' argument, that is a prepared
    statement corresponding to the query.

    This only works on methods of CassandraProxy, as preparing a
    statement requires a connection to a Cassandra server."""
    def decorator(f):
        @functools.wraps(f)
        def newf(self, *args, **kwargs) -> T:
            if f.__name__ not in self._prepared_statements:
                statement: PreparedStatement = self._session.prepare(query)
                self._prepared_statements[f.__name__] = statement
            return f(self, *args, **kwargs,
                     statement=self._prepared_statements[f.__name__])
        return newf
    return decorator


def prepared_insert_statement(table_name: str, columns: List[str]):
    """Shorthand for using `prepared_statement` for `INSERT INTO`
    statements."""
    return prepared_statement(
        'INSERT INTO %s (%s) VALUES (%s)' % (
            table_name,
            ', '.join(columns), ', '.join('?' for _ in columns),
        )
    )


class CassandraProxy:
    def __init__(self, hosts: List[str], keyspace: str, port: int):
        self._cluster = Cluster(
            hosts, port=port, execution_profiles=execution_profiles)
        self._session = self._cluster.connect(keyspace)
        self._cluster.register_user_type(
            keyspace, 'microtimestamp_with_timezone', TimestampWithTimezone)
        self._cluster.register_user_type(
            keyspace, 'microtimestamp', Timestamp)
        self._cluster.register_user_type(
            keyspace, 'person', Person)

        self._prepared_statements: Dict[str, PreparedStatement] = {}

    MAX_RETRIES = 3

    def execute_and_retry(self, statement, args) -> ResultSet:
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
    def increment_counter(
            self, object_type: str, nb: int, *, statement: PreparedStatement
            ) -> None:
        self.execute_and_retry(statement, [nb, object_type])

    def _add_one(
            self, statement, object_type: str, obj, keys: List[str]
            ) -> None:
        self.increment_counter(object_type, 1)
        self.execute_and_retry(
            statement, [getattr(obj, key) for key in keys])

    def _get_random_row(self, statement) -> Optional[Row]:
        '''Takes a prepared stement of the form
        "SELECT * FROM <table> WHERE token(<keys>) > ? LIMIT 1"
        and uses it to return a random row'''
        token = random.randint(TOKEN_BEGIN, TOKEN_END)
        rows = self.execute_and_retry(statement, [token])
        if not rows:
            # There are no row with a greater token; wrap around to get
            # the row with the smallest token
            rows = self.execute_and_retry(statement, [TOKEN_BEGIN])
        if rows:
            return rows.one()
        else:
            return None

    _content_pk = ['sha1', 'sha1_git', 'sha256', 'blake2s256']
    _content_keys = [
        'sha1', 'sha1_git', 'sha256', 'blake2s256', 'length',
        'ctime', 'status']

    @prepared_insert_statement('content', _content_keys)
    def content_add_one(self, content, *, statement) -> None:
        self._add_one(statement, 'content', content, self._content_keys)

    def content_index_add_one(self, main_algo: str, content: Content) -> None:
        query = 'INSERT INTO content_by_{algo} ({cols}) VALUES ({values})' \
            .format(algo=main_algo, cols=', '.join(self._content_pk),
                    values=', '.join('%s' for _ in self._content_pk))
        self.execute_and_retry(
            query, [content.get_hash(algo) for algo in self._content_pk])

    @prepared_statement('SELECT * FROM content WHERE ' +
                        ' AND '.join(map('%s = ?'.__mod__, HASH_ALGORITHMS)))
    def content_get_from_pk(
            self, content_hashes: Dict[str, bytes], *, statement
            ) -> Optional[Row]:
        rows = list(self.execute_and_retry(
            statement, [content_hashes[algo] for algo in HASH_ALGORITHMS]))
        assert len(rows) <= 1
        if rows:
            return rows[0]
        else:
            return None

    @prepared_statement('SELECT * FROM content WHERE token(%s) > ? LIMIT 1'
                        % ', '.join(_content_pk))
    def content_get_random(self, *, statement) -> Optional[Row]:
        return self._get_random_row(statement)

    @prepared_statement(('SELECT token({0}) AS tok, {1} FROM content '
                         'WHERE token({0}) >= ? AND token({0}) <= ? LIMIT ?')
                        .format(', '.join(_content_pk),
                                ', '.join(_content_keys)))
    def content_get_token_range(
            self, start: int, end: int, limit: int, *, statement) -> Row:
        return self.execute_and_retry(statement, [start, end, limit])

    def content_get_pks_from_single_hash(
            self, algo: str, hash_: bytes) -> List[Row]:
        assert algo in HASH_ALGORITHMS
        query = 'SELECT * FROM content_by_{algo} WHERE {algo} = %s'.format(
            algo=algo)
        return list(self.execute_and_retry(query, [hash_]))

    _revision_parent_keys = ['id', 'parent_rank', 'parent_id']

    @prepared_insert_statement('revision_parent', _revision_parent_keys)
    def revision_parent_add_one(
            self, id_: Sha1Git, parent_rank: int, parent_id: Sha1Git, *,
            statement) -> None:
        self.execute_and_retry(
            statement, [id_, parent_rank, parent_id])

    _revision_keys = [
        'id', 'date', 'committer_date', 'type', 'directory', 'message',
        'author', 'committer',
        'synthetic', 'metadata']

    @prepared_insert_statement('revision', _revision_keys)
    def revision_add_one(self, revision: Dict[str, Any], *, statement) -> None:
        self._add_one(statement, 'revision', revision, self._revision_keys)

    @prepared_statement('SELECT id FROM revision WHERE id IN ?')
    def revision_get_ids(self, revision_ids, *, statement) -> ResultSet:
        return self.execute_and_retry(
            statement, [revision_ids])

    @prepared_statement('SELECT * FROM revision WHERE id IN ?')
    def revision_get(self, revision_ids, *, statement) -> ResultSet:
        return self.execute_and_retry(
            statement, [revision_ids])

    @prepared_statement('SELECT parent_id FROM revision_parent WHERE id = ?')
    def revision_get_parents(
            self, revision_id: Sha1Git, *, statement) -> ResultSet:
        return self.execute_and_retry(
            statement, [revision_id])

    @prepared_statement('SELECT * FROM revision WHERE token(id) > ? LIMIT 1')
    def revision_get_random(self, *, statement) -> Optional[Row]:
        return self._get_random_row(statement)

    _release_keys = [
        'id', 'target', 'target_type', 'date', 'name', 'message', 'author',
        'synthetic']

    @prepared_insert_statement('release', _release_keys)
    def release_add_one(self, release: Dict[str, Any], *, statement) -> None:
        self._add_one(statement, 'release', release, self._release_keys)

    @prepared_statement('SELECT * FROM release WHERE id in ?')
    def release_get(self, release_ids: List[str], *, statement) -> None:
        return self.execute_and_retry(statement, [release_ids])

    @prepared_statement('SELECT * FROM release WHERE token(id) > ? LIMIT 1')
    def release_get_random(self, *, statement) -> Optional[Row]:
        return self._get_random_row(statement)

    _directory_keys = ['id']

    @prepared_insert_statement('directory', _directory_keys)
    def directory_add_one(self, directory_id: Sha1Git, *, statement) -> None:
        """Called after all calls to directory_entry_add_one, to
        commit/finalize the directory."""
        self.execute_and_retry(statement, [directory_id])
        self.increment_counter('directory', 1)

    _directory_entry_keys = ['directory_id', 'name', 'type', 'target', 'perms']

    @prepared_insert_statement('directory_entry', _directory_entry_keys)
    def directory_entry_add_one(
            self, entry: Dict[str, Any], *, statement) -> None:
        self.execute_and_retry(
            statement, [entry[key] for key in self._directory_entry_keys])

    @prepared_statement('SELECT * FROM directory_entry '
                        'WHERE directory_id IN ?')
    def directory_entry_get(self, directory_ids, *, statement) -> ResultSet:
        return self.execute_and_retry(
            statement, [directory_ids])

    @prepared_statement('SELECT * FROM directory WHERE token(id) > ? LIMIT 1')
    def directory_get_random(self, *, statement) -> Optional[Row]:
        return self._get_random_row(statement)

    _snapshot_keys = ['id']

    @prepared_statement('SELECT id FROM snapshot WHERE id=? LIMIT 1')
    def snapshot_exists(self, snapshot_id: Sha1Git, *, statement) -> bool:
        return len(list(self.execute_and_retry(statement, [snapshot_id]))) > 0

    @prepared_insert_statement('snapshot', _snapshot_keys)
    def snapshot_add_one(self, snapshot_id: Sha1Git, *, statement) -> None:
        self.execute_and_retry(statement, [snapshot_id])
        self.increment_counter('snapshot', 1)

    _snapshot_branch_keys = ['snapshot_id', 'name', 'target_type', 'target']

    @prepared_insert_statement('snapshot_branch', _snapshot_branch_keys)
    def snapshot_branch_add_one(
            self, branch: Dict[str, Any], *, statement) -> None:
        self.execute_and_retry(
            statement, [branch[key] for key in self._snapshot_branch_keys])

    @prepared_statement('SELECT ascii_bins_count(target_type) AS counts '
                        'FROM snapshot_branch '
                        'WHERE snapshot_id = ? ')
    def snapshot_count_branches(
            self, snapshot_id: Sha1Git, *, statement) -> ResultSet:
        return self.execute_and_retry(statement, [snapshot_id])

    @prepared_statement('SELECT * FROM snapshot '
                        'WHERE id = ?')
    def snapshot_get(self, snapshot_id: Sha1Git, *, statement) -> ResultSet:
        return self.execute_and_retry(statement, [snapshot_id])

    @prepared_statement('SELECT * FROM snapshot_branch '
                        'WHERE snapshot_id = ? AND name >= ?'
                        'LIMIT ?')
    def snapshot_branch_get(
            self, snapshot_id: Sha1Git, from_: bytes, limit: int, *,
            statement) -> None:
        return self.execute_and_retry(statement, [snapshot_id, from_, limit])

    @prepared_statement('SELECT * FROM snapshot WHERE token(id) > ? LIMIT 1')
    def snapshot_get_random(self, *, statement) -> Optional[Row]:
        return self._get_random_row(statement)

    origin_keys = ['sha1', 'url', 'type', 'next_visit_id']

    @prepared_statement('INSERT INTO origin (sha1, url, next_visit_id) '
                        'VALUES (?, ?, 1) IF NOT EXISTS')
    def origin_add_one(self, origin: Dict[str, Any], *, statement) -> None:
        self.execute_and_retry(
            statement, [hash_url(origin['url']), origin['url']])
        self.increment_counter('origin', 1)

    @prepared_statement('SELECT * FROM origin WHERE sha1 = ?')
    def origin_get_by_sha1(self, sha1: bytes, *, statement) -> ResultSet:
        return self.execute_and_retry(statement, [sha1])

    def origin_get_by_url(self, url: str) -> ResultSet:
        return self.origin_get_by_sha1(hash_url(url))

    @prepared_statement(f'SELECT token(sha1) AS tok, {", ".join(origin_keys)} '
                        f'FROM origin WHERE token(sha1) >= ? LIMIT ?')
    def origin_list(
            self, start_token: int, limit: int, *, statement) -> ResultSet:
        return self.execute_and_retry(
            statement, [start_token, limit])

    @prepared_statement('SELECT next_visit_id FROM origin WHERE sha1 = ?')
    def _origin_get_next_visit_id(
            self, origin_sha1: bytes, *, statement) -> int:
        rows = list(self.execute_and_retry(statement, [origin_sha1]))
        assert len(rows) == 1  # TODO: error handling
        return rows[0].next_visit_id

    @prepared_statement('UPDATE origin SET next_visit_id=? '
                        'WHERE sha1 = ? IF next_visit_id=?')
    def origin_generate_unique_visit_id(
            self, origin_url: str, *, statement) -> int:
        origin_sha1 = hash_url(origin_url)
        next_id = self._origin_get_next_visit_id(origin_sha1)
        while True:
            res = list(self.execute_and_retry(
                statement, [next_id+1, origin_sha1, next_id]))
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
        'origin', 'visit', 'type', 'date', 'status', 'metadata', 'snapshot']
    _origin_visit_update_keys = [
        'type', 'date', 'status', 'metadata', 'snapshot']

    @prepared_insert_statement('origin_visit', _origin_visit_keys)
    def origin_visit_add_one(
            self, visit: Dict[str, Any], *, statement) -> None:
        self.execute_and_retry(
            statement, [visit[key] for key in self._origin_visit_keys])
        self.increment_counter('origin_visit', 1)

    @prepared_statement(
        'UPDATE origin_visit SET ' +
        ', '.join('%s = ?' % key for key in _origin_visit_update_keys) +
        ' WHERE origin = ? AND visit = ?')
    def origin_visit_upsert(
            self, visit: Dict[str, Any], *, statement) -> None:
        self.execute_and_retry(
            statement,
            [visit.get(key) for key in self._origin_visit_update_keys]
            + [visit['origin'], visit['visit']])
        # TODO:  check if there is already one
        self.increment_counter('origin_visit', 1)

    @prepared_statement('SELECT * FROM origin_visit '
                        'WHERE origin = ? AND visit = ?')
    def origin_visit_get_one(
            self, origin_url: str, visit_id: int, *,
            statement) -> Optional[Row]:
        # TODO: error handling
        rows = list(self.execute_and_retry(statement, [origin_url, visit_id]))
        if rows:
            return rows[0]
        else:
            return None

    @prepared_statement('SELECT * FROM origin_visit '
                        'WHERE origin = ?')
    def origin_visit_get_all(self, origin_url: str, *, statement) -> ResultSet:
        return self.execute_and_retry(
            statement, [origin_url])

    @prepared_statement('SELECT * FROM origin_visit WHERE origin = ?')
    def origin_visit_get_latest(
            self, origin: str, allowed_statuses: Optional[Iterable[str]],
            require_snapshot: bool, *, statement) -> Optional[Row]:
        # TODO: do the ordering and filtering in Cassandra
        rows = list(self.execute_and_retry(statement, [origin]))

        rows.sort(key=lambda row: (row.date, row.visit), reverse=True)

        for row in rows:
            if require_snapshot and row.snapshot is None:
                continue
            if allowed_statuses is not None \
                    and row.status not in allowed_statuses:
                continue
            if row.snapshot is not None and \
                    not self.snapshot_exists(row.snapshot):
                raise ValueError('visit references unknown snapshot')
            return row
        else:
            return None

    @prepared_statement('SELECT * FROM origin_visit WHERE token(origin) >= ?')
    def _origin_visit_iter_from(
            self, min_token: int, *, statement) -> Generator[Row, None, None]:
        yield from self.execute_and_retry(statement, [min_token])

    @prepared_statement('SELECT * FROM origin_visit WHERE token(origin) < ?')
    def _origin_visit_iter_to(
            self, max_token: int, *, statement) -> Generator[Row, None, None]:
        yield from self.execute_and_retry(statement, [max_token])

    def origin_visit_iter(
            self, start_token: int) -> Generator[Row, None, None]:
        """Returns all origin visits in order from this token,
        and wraps around the token space."""
        yield from self._origin_visit_iter_from(start_token)
        yield from self._origin_visit_iter_to(start_token)

    _tool_keys = ['id', 'name', 'version', 'configuration']

    @prepared_insert_statement('tool_by_uuid', _tool_keys)
    def tool_by_uuid_add_one(self, tool: Dict[str, Any], *, statement) -> None:
        self.execute_and_retry(
            statement, [tool[key] for key in self._tool_keys])

    @prepared_insert_statement('tool', _tool_keys)
    def tool_add_one(self, tool: Dict[str, Any], *, statement) -> None:
        self.execute_and_retry(
            statement, [tool[key] for key in self._tool_keys])
        self.increment_counter('tool', 1)

    @prepared_statement('SELECT id FROM tool '
                        'WHERE name = ? AND version = ? '
                        'AND configuration = ?')
    def tool_get_one_uuid(
            self, name: str, version: str, configuration: Dict[str, Any], *,
            statement) -> Optional[str]:
        rows = list(self.execute_and_retry(
            statement, [name, version, configuration]))
        if rows:
            assert len(rows) == 1
            return rows[0].id
        else:
            return None

    @prepared_statement('SELECT object_type, count FROM object_count '
                        'WHERE partition_key=0')
    def stat_counters(self, *, statement) -> ResultSet:
        return self.execute_and_retry(
            statement, [])


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
        contents = [Content.from_dict(c) for c in contents]

        # Filter-out content already in the database.
        contents = [c for c in contents
                    if not self._proxy.content_get_from_pk(c.to_dict())]

        if self.journal_writer:
            for content in contents:
                content = content.to_dict()
                if 'data' in content:
                    del content['data']
                self.journal_writer.write_addition('content', content)

        count_contents = 0
        count_content_added = 0
        count_content_bytes_added = 0

        for content in contents:
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
                    algo, content.get_hash(algo))
                if len(pks) > 1:
                    # There are more than the one we just inserted.
                    from . import HashCollision
                    raise HashCollision(algo, content.get_hash(algo), pks)

            count_contents += 1
            if content.status != 'absent':
                count_content_added += 1
                if with_data:
                    content_data = content.data
                    count_content_bytes_added += len(content_data)
                    self.objstorage.add(content_data, content.sha1)

        summary = {
            'content:add': count_content_added,
            'skipped_content:add': count_contents - count_content_added,
        }

        if with_data:
            summary['content:add:bytes'] = count_content_bytes_added

        return summary

    def content_add(self, content):
        content = [dict(c.items()) for c in content]  # semi-shallow copy
        for item in content:
            item['ctime'] = now()
        return self._content_add(content, with_data=True)

    def content_add_metadata(self, content):
        return self._content_add(content, with_data=False)

    def content_get(self, content):
        if len(content) > BULK_BLOCK_CONTENT_LEN_MAX:
            raise ValueError(
                "Sending at most %s contents." % BULK_BLOCK_CONTENT_LEN_MAX)
        for obj_id in content:
            try:
                data = self.objstorage.get(obj_id)
            except ObjNotFoundError:
                yield None
                continue

            yield {'sha1': obj_id, 'data': data}

    def content_get_partition(
            self, partition_id: int, nb_partitions: int, limit: int = 1000,
            page_token: str = None):
        if limit is None:
            raise ValueError('Development error: limit should not be None')
        partition_size = (TOKEN_END-TOKEN_BEGIN)//nb_partitions
        range_start = TOKEN_BEGIN + partition_id*partition_size
        range_end = TOKEN_BEGIN + (partition_id+1)*partition_size
        if page_token is not None:
            if not (range_start <= int(page_token) <= range_end):
                raise ValueError('Invalid page_token.')
            range_start = int(page_token)

        rows = self._proxy.content_get_token_range(
            range_start, range_end, limit)
        rows = list(rows)

        if len(rows) == limit:
            next_page_token: Optional[str] = str(rows[-1].tok+1)
        else:
            next_page_token = None

        return {
            'contents': [row._asdict() for row in rows
                         if row.status != 'absent'],
            'next_page_token': next_page_token,
        }

    def content_get_metadata(self, contents):
        result = {sha1: [] for sha1 in contents}
        for sha1 in contents:
            pks = self._proxy.content_get_pks_from_single_hash('sha1', sha1)
            if pks:
                # TODO: what to do if there are more than one?
                pk = pks[0]
                res = self._proxy.content_get_from_pk(pk._asdict())
                # Rows in 'content' are inserted after corresponding
                # rows in 'content_by_*', so we might be missing it
                if res:
                    content_metadata = res._asdict()
                    content_metadata.pop('ctime')
                    result[content_metadata['sha1']].append(content_metadata)
        return result

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
            # Rows in 'content' are inserted after corresponding
            # rows in 'content_by_*', so we might be missing it
            if res:
                results.append({
                    **res._asdict(),
                    'ctime': res.ctime.replace(tzinfo=datetime.timezone.utc)
                })
        return results

    def content_missing(self, content, key_hash='sha1'):
        for cont in content:
            res = self.content_find(cont)
            if not res:
                yield cont[key_hash]
            if any(c['status'] == 'missing' for c in res):
                yield cont[key_hash]

    def content_missing_per_sha1(self, contents):
        return self.content_missing([{'sha1': c for c in contents}])

    def content_get_random(self):
        return self._proxy.content_get_random().sha1_git

    def directory_add(self, directories):
        missing = self.directory_missing([dir_['id'] for dir_ in directories])
        directories = [dir_ for dir_ in directories if dir_['id'] in missing]

        if self.journal_writer:
            self.journal_writer.write_additions('directory', directories)

        for directory in directories:
            directory = Directory.from_dict(directory)

            for entry in directory.entries:
                entry = entry.to_dict()
                entry['directory_id'] = directory.id
                self._proxy.directory_entry_add_one(entry)

            # Add the directory *after* adding all the entries, so someone
            # calling snapshot_get_branch in the meantime won't end up
            # with half the entries.
            self._proxy.directory_add_one(directory.id)

        return {'directory:add': len(missing)}

    def directory_missing(self, directories):
        return self._missing('directory', directories)

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
                content = content[0]
                for key in keys:
                    ret[key] = content[key]
        return ret

    def _directory_ls(self, directory_id, recursive, prefix=b''):
        if self.directory_missing([directory_id]):
            return
        rows = list(self._proxy.directory_entry_get([directory_id]))

        for row in rows:
            entry = row._asdict()
            del entry['directory_id']
            entry = DirectoryEntry.from_dict(entry)
            ret = self._join_dentry_to_content(entry)
            ret['name'] = prefix + ret['name']
            ret['dir_id'] = directory_id
            yield ret
            if recursive and ret['type'] == 'dir':
                yield from self._directory_ls(
                    ret['target'], True, prefix + ret['name'] + b'/')

    def directory_entry_get_by_path(self, directory, paths):
        return self._directory_entry_get_by_path(directory, paths, b'')

    def _directory_entry_get_by_path(self, directory, paths, prefix):
        if not paths:
            return

        contents = list(self.directory_ls(directory))

        if not contents:
            return

        def _get_entry(entries, name):
            for entry in entries:
                if entry['name'] == name:
                    entry = entry.copy()
                    entry['name'] = prefix + entry['name']
                    return entry

        first_item = _get_entry(contents, paths[0])

        if len(paths) == 1:
            return first_item

        if not first_item or first_item['type'] != 'dir':
            return

        return self._directory_entry_get_by_path(
                first_item['target'], paths[1:], prefix + paths[0] + b'/')

    def directory_ls(self, directory, recursive=False):
        yield from self._directory_ls(directory, recursive)

    def directory_get_random(self):
        return self._proxy.directory_get_random().id

    def revision_add(self, revisions, check_missing=True):
        if check_missing:
            missing = self.revision_missing([rev['id'] for rev in revisions])
            revisions = [rev for rev in revisions if rev['id'] in missing]

        if self.journal_writer:
            self.journal_writer.write_additions('revision', revisions)

        for revision in revisions:
            if check_missing and revision['id'] not in missing:
                continue

            revision = revision_to_db(revision)

            if revision:
                for (rank, parent) in enumerate(revision.parents):
                    self._proxy.revision_parent_add_one(
                        revision.id, rank, parent)

                # Write this after all parents were written ensures that read
                # endpoints don't return a partial view while writing the
                # parents
                self._proxy.revision_add_one(revision)

        if check_missing:
            return {'revision:add': len(missing)}
        else:
            return {'revision:add': len(revisions)}

    def revision_missing(self, revisions):
        return self._missing('revision', revisions)

    def revision_get(self, revisions):
        rows = self._proxy.revision_get(revisions)
        revs = {}
        for row in rows:
            # TODO: use a single query to get all parents?
            # (it might have less latency, but requires less code and more
            # bandwidth (because revision id would be part of each returned
            # row)
            parent_rows = self._proxy.revision_get_parents(row.id)
            # parent_rank is the clustering key, so results are already
            # sorted by rank.
            parents = [row.parent_id for row in parent_rows]

            rev = Revision(**row._asdict(), parents=parents)

            rev = revision_from_db(rev)
            revs[rev.id] = rev.to_dict()

        for rev_id in revisions:
            yield revs.get(rev_id)

    def _get_parent_revs(self, rev_ids, seen, limit, short):
        if limit and len(seen) >= limit:
            return
        rev_ids = [id_ for id_ in rev_ids if id_ not in seen]
        if not rev_ids:
            return
        seen |= set(rev_ids)

        # We need this query, even if short=True, to return consistent
        # results (ie. not return only a subset of a revision's parents
        # if it is being written)
        if short:
            rows = self._proxy.revision_get_ids(rev_ids)
        else:
            rows = self._proxy.revision_get(rev_ids)

        for row in rows:
            # TODO: use a single query to get all parents?
            # (it might have less latency, but requires less code and more
            # bandwidth (because revision id would be part of each returned
            # row)
            parent_rows = self._proxy.revision_get_parents(row.id)

            # parent_rank is the clustering key, so results are already
            # sorted by rank.
            parents = [row.parent_id for row in parent_rows]

            if short:
                yield (row.id, parents)
            else:
                rev = revision_from_db(Revision(
                    **row._asdict(), parents=parents))
                yield rev.to_dict()
            yield from self._get_parent_revs(parents, seen, limit, short)

    def revision_log(self, revisions, limit=None):
        """Fetch revision entry from the given root revisions.

        Args:
            revisions: array of root revision to lookup
            limit: limitation on the output result. Default to None.

        Yields:
            List of revision log from such revisions root.

        """
        seen = set()
        yield from self._get_parent_revs(revisions, seen, limit, False)

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

    def revision_get_random(self):
        return self._proxy.revision_get_random().id

    def release_add(self, releases):
        missing = self.release_missing([rel['id'] for rel in releases])
        releases = [rel for rel in releases if rel['id'] in missing]

        if self.journal_writer:
            self.journal_writer.write_additions('release', releases)

        for release in releases:
            release = release_to_db(release)

            if release:
                self._proxy.release_add_one(release)

        return {'release:add': len(missing)}

    def release_missing(self, releases):
        return self._missing('release', releases)

    def release_get(self, releases):
        rows = self._proxy.release_get(releases)
        rels = {}
        for row in rows:
            release = Release(**row._asdict())
            release = release_from_db(release)
            rels[row.id] = release.to_dict()

        for rel_id in releases:
            yield rels.get(rel_id)

    def release_get_random(self):
        return self._proxy.release_get_random().id

    def snapshot_add(self, snapshots, origin=None, visit=None):
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
        visit = self.origin_visit_get_latest(
            origin,
            allowed_statuses=allowed_statuses,
            require_snapshot=True)

        if visit:
            assert visit['snapshot']
            if not self._proxy.snapshot_exists(visit['snapshot']):
                raise ValueError('Visit references unknown snapshot')
            return self.snapshot_get_branches(visit['snapshot'])

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

        branches = []
        while len(branches) < branches_count+1:
            new_branches = list(self._proxy.snapshot_branch_get(
                snapshot_id, branches_from, branches_count+1))

            if not new_branches:
                break

            branches_from = new_branches[-1].name

            new_branches_filtered = new_branches

            if target_types:
                new_branches_filtered = [
                    branch for branch in new_branches_filtered
                    if branch.target is not None
                    and branch.target_type in target_types]

            branches.extend(new_branches_filtered)

            if len(new_branches) < branches_count+1:
                break

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

        return {
            'id': snapshot_id,
            'branches': branches,
            'next_branch': last_branch,
        }

    def snapshot_get_random(self):
        return self._proxy.snapshot_get_random().id

    OBJECT_FIND_TYPES = ('revision', 'release', 'content', 'directory')
    # Mind the order, revision is the most likely one for a given ID,
    # so we check revisions first.

    def object_find_by_sha1_git(self, ids):
        results = {id_: [] for id_ in ids}
        missing_ids = set(ids)

        for object_type in self.OBJECT_FIND_TYPES:
            if object_type == 'content':
                query = (
                    'SELECT sha1 AS id, sha1_git FROM content_by_sha1_git '
                    'WHERE sha1_git IN ({values})')
            else:
                query = (
                    'SELECT id, id AS sha1_git FROM {table} '
                    'WHERE id IN ({values})')
            query = query.format(
                table=object_type,
                values=', '.join('%s' for _ in missing_ids))
            rows = self._proxy.execute_and_retry(
                query, missing_ids)
            for row in rows:
                results[row.sha1_git].append({
                    'id': row.id,
                    'sha1_git': row.sha1_git,
                    'type': object_type,
                })
                missing_ids.remove(row.sha1_git)

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
            raise ValueError('Origin ids are not supported.')
        rows = self._proxy.origin_get_by_url(origin['url'])

        rows = list(rows)
        if rows:
            assert len(rows) == 1
            result = rows[0]._asdict()
            return {
                'url': result['url'],
            }
        else:
            return None

    def origin_get_by_sha1(self, sha1s):
        results = []
        for sha1 in sha1s:
            rows = self._proxy.origin_get_by_sha1(sha1)
            if rows:
                results.append({'url': rows.one().url})
            else:
                results.append(None)
        return results

    def origin_list(self, page_token: Optional[str] = None, limit: int = 100
                    ) -> dict:
        start_token = TOKEN_BEGIN
        if page_token:
            start_token = int(page_token)
            if not (TOKEN_BEGIN <= start_token <= TOKEN_END):
                raise ValueError('Invalid page_token.')

        rows = self._proxy.origin_list(start_token, limit)
        rows = list(rows)

        if len(rows) == limit:
            next_page_token: Optional[str] = str(rows[-1].tok+1)
        else:
            next_page_token = None

        return {
            'origins': [{'url': row.url} for row in rows],
            'next_page_token': next_page_token,
        }

    def origin_search(self, url_pattern, offset=0, limit=50,
                      regexp=False, with_visit=False):
        # TODO: do some filtering on the Cassandra side
        origins = self._proxy.execute_and_retry('SELECT * FROM origin', [])
        if regexp:
            pat = re.compile(url_pattern)
            origins = [orig for orig in origins if pat.search(orig.url)]
        else:
            origins = [orig for orig in origins if url_pattern in orig.url]

        if with_visit:
            origins = [orig for orig in origins
                       if orig.next_visit_id > 1]

        return [
            {
                'url': orig.url,
            }
            for orig in origins[offset:offset+limit]]

    def origin_add(self, origins):
        if any('id' in origin for origin in origins):
            raise ValueError('Origins must not already have an id.')
        results = []
        for origin in origins:
            self.origin_add_one(origin)
            results.append(origin)
        return results

    def origin_add_one(self, origin):
        known_origin = self.origin_get_one(origin)

        if known_origin:
            origin_url = known_origin['url']
        else:
            if self.journal_writer:
                self.journal_writer.write_addition('origin', origin)

            self._proxy.origin_add_one(origin)
            origin_url = origin['url']

        return origin_url

    def origin_visit_add(self, origin, date=None, type=None, *, ts=None):
        if ts is None:
            if date is None:
                raise TypeError('origin_visit_add expected 2 arguments.')
        else:
            assert date is None
            warnings.warn("argument 'ts' of origin_visit_add was renamed "
                          "to 'date' in v0.0.109.",
                          DeprecationWarning)
            date = ts

        origin_url = origin  # TODO: rename the argument

        if isinstance(date, str):
            date = dateutil.parser.parse(date)

        origin = self.origin_get_one({'url': origin_url})

        if not origin:
            return None

        visit_id = self._proxy.origin_generate_unique_visit_id(origin_url)

        visit = {
            'origin': origin_url,
            'date': date,
            'type': type,
            'status': 'ongoing',
            'snapshot': None,
            'metadata': None,
            'visit': visit_id
        }

        if self.journal_writer:
            self.journal_writer.write_addition('origin_visit', visit)

        self._proxy.origin_visit_add_one(visit)

        return {
                'origin': origin_url,
                'visit': visit_id,
            }

    def origin_visit_update(self, origin, visit_id, status=None,
                            metadata=None, snapshot=None):
        origin_url = origin  # TODO: rename the argument

        row = self._proxy.origin_visit_get_one(origin_url, visit_id)
        if not row:
            raise ValueError('This origin visit does not exist.')
        visit = OriginVisit.from_dict(self._format_origin_visit_row(row))

        updates = {}
        if status:
            updates['status'] = status
        if metadata:
            updates['metadata'] = metadata
        if snapshot:
            updates['snapshot'] = snapshot

        set_parts = []
        args = []
        for (column, value) in updates.items():
            set_parts.append(f'{column} = %s')
            if column == 'metadata':
                args.append(json.dumps(value))
            else:
                args.append(value)

        visit = attr.evolve(visit, **updates)

        if self.journal_writer:
            self.journal_writer.write_update('origin_visit', visit)

        if not set_parts:
            return

        query = ('UPDATE origin_visit SET ' + ', '.join(set_parts) +
                 ' WHERE origin = %s AND visit = %s')
        self._proxy.execute_and_retry(
            query, args + [origin_url, visit_id])

    def origin_visit_upsert(self, visits):
        visits = [visit.copy() for visit in visits]
        for visit in visits:
            if isinstance(visit['date'], str):
                visit['date'] = dateutil.parser.parse(visit['date'])

        if self.journal_writer:
            for visit in visits:
                self.journal_writer.write_addition('origin_visit', visit)

        for visit in visits:
            visit = visit.copy()
            if visit.get('metadata'):
                visit['metadata'] = json.dumps(visit['metadata'])
            self._proxy.origin_visit_upsert(visit)

    @staticmethod
    def _format_origin_visit_row(visit):
        return {
            **visit._asdict(),
            'origin': visit.origin,
            'date': visit.date.replace(tzinfo=datetime.timezone.utc),
            'metadata': (json.loads(visit.metadata)
                         if visit.metadata else None),
        }

    def origin_visit_get(self, origin, last_visit=None, limit=None):
        query_parts = ['SELECT * FROM origin_visit WHERE', 'origin=%s']
        args = [origin]

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

    def origin_visit_find_by_date(self, origin, visit_date):
        visits = list(self._proxy.origin_visit_get_all(origin))

        def key(visit):
            dt = visit.date.replace(tzinfo=datetime.timezone.utc) - visit_date
            return (abs(dt), -visit.visit)

        if visits:
            visit = min(visits, key=key)
            return visit._asdict()

    def origin_visit_get_by(self, origin, visit):
        visit = self._proxy.origin_visit_get_one(origin, visit)
        if visit:
            return self._format_origin_visit_row(visit)

    def origin_visit_get_latest(
            self, origin, allowed_statuses=None, require_snapshot=False):
        visit = self._proxy.origin_visit_get_latest(
            origin,
            allowed_statuses=allowed_statuses,
            require_snapshot=require_snapshot)
        if visit:
            return self._format_origin_visit_row(visit)

    def origin_visit_get_random(self, type: str) -> Optional[Dict[str, Any]]:
        back_in_the_day = now() - datetime.timedelta(weeks=12)  # 3 months back
        start_token = random.randint(TOKEN_BEGIN, TOKEN_END)

        # Iterator over all visits, ordered by origins then visit_id
        rows = self._proxy.origin_visit_iter(start_token)
        for row in rows:
            visit = self._format_origin_visit_row(row)
            if visit['date'] > back_in_the_day \
                    and visit['status'] == 'full':
                return visit
        else:
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
        rows = self._proxy.stat_counters()
        keys = (
            'content', 'directory', 'origin', 'origin_visit',
            'release', 'revision', 'skipped_content', 'snapshot')
        stats = {key: 0 for key in keys}
        stats.update({row.object_type: row.count for row in rows})
        return stats

    def refresh_stat_counters(self):
        pass

    def fetch_history_start(self, origin_url):
        """Add an entry for origin origin_url in fetch_history. Returns the id
        of the added fetch_history entry
        """
        pass

    def fetch_history_end(self, fetch_history_id, data):
        """Close the fetch_history entry with id `fetch_history_id`, replacing
           its data with `data`.
        """
        pass

    def fetch_history_get(self, fetch_history_id):
        """Get the fetch_history entry with id `fetch_history_id`.
        """
        raise NotImplementedError('fetch_history_get is deprecated, use '
                                  'origin_visit_get instead.')
