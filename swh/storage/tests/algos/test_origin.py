# Copyright (C) 2019  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import unittest
from unittest.mock import patch

from swh.storage.in_memory import Storage
from swh.storage.algos.origin import iter_origins


def assert_count_eq(left, right, msg=None):
    unittest.TestCase().assertCountEqual(list(left), list(right), msg)


def test_iter_origins():
    storage = Storage()
    origins = storage.origin_add([
        {'url': 'bar'},
        {'url': 'qux'},
        {'url': 'quuz'},
    ])
    origins.sort(key=lambda orig: orig['id'])
    assert_count_eq(iter_origins(storage), origins)
    assert_count_eq(iter_origins(storage, batch_size=1), origins)
    assert_count_eq(iter_origins(storage, batch_size=2), origins)

    for i in range(0, 3):
        assert_count_eq(
            iter_origins(storage, origin_from=origins[i]['id']),
            origins[i:],
            i)

        assert_count_eq(
            iter_origins(storage, origin_from=origins[i]['id'],
                         batch_size=1),
            origins[i:],
            i)

        assert_count_eq(
            iter_origins(storage, origin_from=origins[i]['id'],
                         batch_size=2),
            origins[i:],
            i)

        for j in range(i, 3):
            assert_count_eq(
                iter_origins(
                    storage, origin_from=origins[i]['id'],
                    origin_to=origins[j]['id']),
                origins[i:j],
                (i, j))

            assert_count_eq(
                iter_origins(
                    storage, origin_from=origins[i]['id'],
                    origin_to=origins[j]['id'], batch_size=1),
                origins[i:j],
                (i, j))

            assert_count_eq(
                iter_origins(
                    storage, origin_from=origins[i]['id'],
                    origin_to=origins[j]['id'], batch_size=2),
                origins[i:j],
                (i, j))


@patch('swh.storage.in_memory.Storage.origin_get_range')
def test_iter_origins_batch_size(mock_origin_get_range):
    storage = Storage()
    mock_origin_get_range.return_value = []

    list(iter_origins(storage))
    mock_origin_get_range.assert_called_with(
        origin_from=b'\x00'*20, origin_count=10000)

    list(iter_origins(storage, batch_size=42))
    mock_origin_get_range.assert_called_with(
        origin_from=b'\x00'*20, origin_count=42)
