# Copyright (C) 2018-2019  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import os
import signal
import socket
import subprocess
import time

import pytest

from swh.storage import get_storage
from swh.storage.cassandra import create_keyspace

from swh.storage.tests.test_storage import TestStorage as _TestStorage
from swh.storage.tests.test_storage import TestStorageGeneratedData \
    as _TestStorageGeneratedData


CONFIG_TEMPLATE = '''
data_file_directories:
    - {data_dir}/data
commitlog_directory: {data_dir}/commitlog
hints_directory: {data_dir}/hints
saved_caches_directory: {data_dir}/saved_caches

commitlog_sync: periodic
commitlog_sync_period_in_ms: 1000000
partitioner: org.apache.cassandra.dht.Murmur3Partitioner
endpoint_snitch: SimpleSnitch
seed_provider:
    - class_name: org.apache.cassandra.locator.SimpleSeedProvider
      parameters:
          - seeds: "127.0.0.1"

storage_port: {storage_port}
native_transport_port: {native_transport_port}
start_native_transport: true
listen_address: 127.0.0.1

enable_user_defined_functions: true
'''


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_for_peer(addr, port):
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((addr, port))
        except ConnectionRefusedError:
            time.sleep(0.1)
        else:
            sock.close()
            break


@pytest.fixture(scope='session')
def cassandra_cluster(tmpdir_factory):
    cassandra_conf = tmpdir_factory.mktemp('cassandra_conf')
    cassandra_data = tmpdir_factory.mktemp('cassandra_data')
    cassandra_log = tmpdir_factory.mktemp('cassandra_log')
    native_transport_port = free_port()
    storage_port = free_port()
    jmx_port = free_port()

    with open(str(cassandra_conf.join('cassandra.yaml')), 'w') as fd:
        fd.write(CONFIG_TEMPLATE.format(
            data_dir=str(cassandra_data),
            storage_port=storage_port,
            native_transport_port=native_transport_port,
        ))

    if os.environ.get('LOG_CASSANDRA'):
        stdout = stderr = None
    else:
        stdout = stderr = subprocess.DEVNULL
    proc = subprocess.Popen(
        [
            '/usr/sbin/cassandra',
            '-Dcassandra.config=file://%s/cassandra.yaml' % cassandra_conf,
            '-Dcassandra.logdir=%s' % cassandra_log,
            '-Dcassandra.jmx.local.port=%d' % jmx_port,
        ],
        start_new_session=True,
        env={
            'MAX_HEAP_SIZE': '200M',
            'HEAP_NEWSIZE': '20M',
            'JVM_OPTS': '-Xlog:gc=error:file=%s/gc.log' % cassandra_log
        },
        stdout=stdout,
        stderr=stderr,
    )

    wait_for_peer('127.0.0.1', native_transport_port)

    yield (['127.0.0.1'], native_transport_port)

    # print(open(str(cassandra_data.join('log/debug.log'))).read())

    pgrp = os.getpgid(proc.pid)
    os.killpg(pgrp, signal.SIGKILL)


class RequestHandler:
    def on_request(self, rf):
        if hasattr(rf.message, 'query'):
            print()
            print(rf.message.query)


# tests are executed using imported classes (TestStorage and
# TestStorageGeneratedData) using overloaded swh_storage fixture
# below

@pytest.fixture
def swh_storage(cassandra_cluster):
    (hosts, port) = cassandra_cluster
    keyspace = os.urandom(10).hex()

    create_keyspace(hosts, keyspace, port)

    storage = get_storage(
        'cassandra',
        hosts=hosts, port=port,
        keyspace=keyspace,
        journal_writer={
            'cls': 'memory',
        },
        objstorage={
            'cls': 'memory',
            'args': {},
        },
    )

    yield storage

    storage._proxy._session.execute(
        'DROP KEYSPACE "%s"' % keyspace)


class TestCassandraStorage(_TestStorage):
    @pytest.mark.skip('postgresql-specific test')
    def test_content_add_db(self):
        pass

    @pytest.mark.skip('postgresql-specific test')
    def test_skipped_content_add_db(self):
        pass

    @pytest.mark.skip('postgresql-specific test')
    def test_content_add_metadata_db(self):
        pass

    @pytest.mark.skip(
        'not implemented, see https://forge.softwareheritage.org/T1633')
    def test_skipped_content_add(self):
        pass

    @pytest.mark.skip(
        'The "person" table of the pgsql is a legacy thing, and not '
        'supported by the cassandra backend.')
    def test_person_get_fullname_unicity(self):
        pass

    @pytest.mark.skip(
        'The "person" table of the pgsql is a legacy thing, and not '
        'supported by the cassandra backend.')
    def test_person_get(self):
        pass

    @pytest.mark.skip('Not yet implemented')
    def test_metadata_provider_add(self):
        pass

    @pytest.mark.skip('Not yet implemented')
    def test_metadata_provider_get(self):
        pass

    @pytest.mark.skip('Not yet implemented')
    def test_metadata_provider_get_by(self):
        pass

    @pytest.mark.skip('Not yet implemented')
    def test_origin_metadata_add(self):
        pass

    @pytest.mark.skip('Not yet implemented')
    def test_origin_metadata_get(self):
        pass

    @pytest.mark.skip('Not yet implemented')
    def test_origin_metadata_get_by_provider_type(self):
        pass

    @pytest.mark.skip('Not supported by Cassandra')
    def test_origin_count(self):
        pass


class TestCassandraStorageGeneratedData(_TestStorageGeneratedData):
    @pytest.mark.skip('Not supported by Cassandra')
    def test_origin_count(self):
        pass

    @pytest.mark.skip('Not supported by Cassandra')
    def test_origin_get_range(self):
        pass

    @pytest.mark.skip('Not supported by Cassandra')
    def test_generate_content_get_range_limit(self):
        pass

    @pytest.mark.skip('Not supported by Cassandra')
    def test_generate_content_get_range_no_limit(self):
        pass

    @pytest.mark.skip('Not supported by Cassandra')
    def test_generate_content_get_range(self):
        pass

    @pytest.mark.skip('Not supported by Cassandra')
    def test_generate_content_get_range_empty(self):
        pass

    @pytest.mark.skip('Not supported by Cassandra')
    def test_generate_content_get_range_limit_none(self):
        pass

    @pytest.mark.skip('Not supported by Cassandra')
    def test_generate_content_get_range_full(self):
        pass
