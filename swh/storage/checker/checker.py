# Copyright (C) 2015-2016  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import click
import logging

from swh.core import config, hashutil
from .. import get_storage
from ..objstorage import ObjStorage
from ..exc import ObjNotFoundError, Error

DEFAULT_CONFIG = {
    'storage_path': ('str', '/srv/softwareheritage/objects'),
    'storage_depth': ('int', 3),
    'backup_url': ('str', 'http://uffizi:5002'),

    'batch_size': ('int', 1000),
}


class ContentChecker():
    """ Content integrity checker that will check local objstorage content.

    The checker will check the data of an object storage in order to verify
    that no file have been corrupted.

    Attributes:
        config: dictionary that contains this
            checker configuration
        objstorage (ObjStorage): Local object storage that will be checked.
        master_storage (RemoteStorage): A distant storage that will be used to
            restore corrupted content.
    """

    def __init__(self, config, root, depth, backup_url):
        """ Create a checker that ensure the objstorage have no corrupted file.

        Args:
            config (dict): Dictionary that contains the following keys :
                batch_size: Number of content that should be tested each
                    time the content checker runs.
            root (string): Path to the objstorage directory
            depth (int): Depth of the object storage.
            master_url (string): Url of a storage that can be used to restore
                content.
        """
        self.config = config
        self.objstorage = ObjStorage(root, depth)
        self.backup_storage = get_storage('remote_storage', [backup_url])

    def run(self):
        """ Start the check routine
        """
        corrupted_contents = []
        batch_size = self.config['batch_size']

        for content_id in self.get_content_to_check(batch_size):
            if not self.check_content(content_id):
                self.invalidate_content(content_id)
                corrupted_contents.append(content_id)
                logging.error('The content', content_id, 'have been corrupted')

        self.repair_contents(corrupted_contents)

    def get_content_to_check(self, batch_size):
        """ Get the content that should be verified.

        Returns:
            An iterable of the content's id that need to be checked.
        """
        contents = self.objstorage.get_random_contents(batch_size)
        yield from contents

    def check_content(self, content_id):
        """ Check the validity of the given content.

        Returns:
            True if the content was valid, false if it was corrupted.
        """
        try:
            self.objstorage.check(content_id)
        except (ObjNotFoundError, Error) as e:
            logging.error(e)
            return False
        else:
            return True

    def repair_contents(self, content_ids):
        """ Try to restore the given contents.
        """
        # Retrieve the data of the corrupted contents from the master storage.
        contents = self.backup_storage.content_get(content_ids)
        contents_set = set(content_ids)
        # Erase corrupted version with new safe one.
        for content in contents:
            if not content:
                continue
            data = content['data']
            contents_set.discard(content['sha1'])
            self.objstorage.restore_bytes(data)

        if contents_set:
            logging.error("Some corrupted contents could not be retrieved : %s"
                          % [hashutil.hash_to_hex(id) for id in contents_set])


@click.command()
@click.argument('config-path', required=1)
@click.option('--storage-path', default=DEFAULT_CONFIG['storage_path'],
              help='Path to the storage to verify')
@click.option('--depth', default=DEFAULT_CONFIG['storage_depth'],
              type=click.INT, help='Depth of the object storage')
@click.option('--backup-url', default=DEFAULT_CONFIG['backup_url'],
              help='Url of a remote storage to retrieve corrupted content')
def launch(config_path, storage_path, depth, backup_url):
    # The configuration have following priority :
    # command line > file config > default config
    cl_config = {
        'storage_path': storage_path,
        'storage_depth': depth,
        'backup_url': backup_url
    }
    conf = config.read(config_path, DEFAULT_CONFIG)
    conf.update(cl_config)
    # Create the checker and run
    checker = ContentChecker(
        {'batch_size': conf['batch_size']},
        conf['storage_path'],
        conf['depth'],
        conf['backup_url']
    )
    checker.run()
