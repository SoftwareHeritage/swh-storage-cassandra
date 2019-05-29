# Copyright (C) 2019  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information


def iter_origins(
        storage, origin_from=b'\x00'*20, origin_to=None, batch_size=10000):
    """Iterates over all origins in the storage.

    Args:
        storage: the storage object used for queries.
        batch_size: number of origins per query
    Yields:
        dict: the origin dictionary with the keys:

        - id: origin's id
        - url: origin's url
    """
    start = origin_from
    while start is not None:
        origins = list(storage.origin_get_range(
            origin_from=start, origin_count=max(2, batch_size)))
        if len(origins) > 1:
            start = origins[-1]['id']
            origins = origins[0:-1]
        else:
            start = None

        for origin in origins:
            if origin_to and origin['id'] >= origin_to:
                return
            yield origin
