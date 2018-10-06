#!/usr/bin/env python3

import argparse
import hashlib
import os
import shutil
import sys


class Error(Exception):
    pass


class Repository(object):
    def __init__(self, path=''):
        self._apt_path = path
        self._makeapt_path = os.path.join(self._apt_path, '.makeapt')
        self._pool_path = os.path.join(self._apt_path, 'pool')

        # Buffer size for file I/O, in bytes.
        self._BUFF_SIZE = 4096

    def _make_dir(self, path):
        os.makedirs(path)

    def _make_file_dir(self, path):
        self._make_dir(os.path.dirname(path))

    def init(self):
        '''Initializes APT repository.'''
        self._make_dir(self._makeapt_path)
        self._make_dir(self._pool_path)

    def _hash_file(self, path, hashfunc):
        msg = hashfunc()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(self._BUFF_SIZE), b''):
                msg.update(chunk)
        return msg.hexdigest()

    def _copy_file(self, src, dest):
        self._make_file_dir(dest)
        shutil.copyfile(src, dest)

    def _add_package(self, path):
        # Copy the package to the pool.
        hash = self._hash_file(path, hashlib.sha1)

        path_in_pool = os.path.join(self._pool_path, hash[:2], hash[2:],
                                    os.path.basename(path))
        self._copy_file(path, path_in_pool)

    def add(self, paths):
        '''Adds packages to repository.'''
        for path in paths:
            self._add_package(path)


class CommandLineDriver(object):
    def __init__(self):
        self._prog_name = os.path.basename(sys.argv[0])

        self.COMMANDS = {
            'add': (self.add, 'Add .deb packages to repository.'),
            'init': (self.init, 'Initialize APT repository.'),
        }

    def init(self, repo, parser, args):
        args = parser.parse_args(args)
        repo.init()

    def add(self, repo, parser, args):
        parser.add_argument('package', nargs='+',
                            help='The packages to add.')
        args = parser.parse_args(args)
        repo.add(args.package)

    def execute_command_line(self, args):
        parser = argparse.ArgumentParser(
            prog=self._prog_name,
            description='Debian APT repositories generator')
        parser.add_argument('command', help='The command to run.')

        command = sys.argv[1:2]
        command_args = sys.argv[2:]

        args = parser.parse_args(command)
        if args.command not in self.COMMANDS:
            raise Error('Unknown command %r.' % args.command)

        handler, descr = self.COMMANDS[args.command]
        command_parser = argparse.ArgumentParser(
            prog='%s %s' % (self._prog_name, args.command),
            description=descr)

        repo = Repository()

        handler(repo, command_parser, command_args)

    def run(self):
        self.execute_command_line(sys.argv[1:])


def main():
    driver = CommandLineDriver()
    driver.run()


if __name__ == '__main__':
    main()
