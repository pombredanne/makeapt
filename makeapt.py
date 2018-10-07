#!/usr/bin/env python3

import argparse
import ast
import hashlib
import os
import shutil
import subprocess
import sys


class Error(Exception):
    pass


class Repository(object):
    # We prefer these fields always be specified in this order.
    DEB_INFO_FIELDS = [
        'Package',
        'Version',
        'Section',
        'Priority',
        'Architecture',
        'Installed-Size',
        'Depends',
        'Maintainer',
        'Uploaders',
        'Homepage',
        'Description',
    ]

    # Buffer size for file I/O, in bytes.
    _BUFF_SIZE = 4096

    def __init__(self, path='.'):
        self._apt_path = path

    def __enter__(self):
        self._makeapt_path = os.path.join(self._apt_path, '.makeapt')
        self._index_path = os.path.join(self._makeapt_path, 'index')
        self._pool_path = os.path.join(self._apt_path, 'pool')

        # TODO: Lock the repository.

        self._load_index()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._save_index()
        # TODO: Unlock the repository.

    def _make_dir(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def _make_file_dir(self, path):
        self._make_dir(os.path.dirname(path))

    def init(self):
        '''Initializes APT repository.'''
        self._make_dir(self._makeapt_path)
        self._make_dir(self._pool_path)

    def _load_literal(self, path, default):
        try:
            with open(path, 'r') as f:
                return ast.literal_eval(f.read())
        except FileNotFoundError:
            return default

    # Writes a given value in consistent and human-readable way.
    def _emit_literal(self, value, level=0):
        indent = ' '
        nested_level = level + 1
        if isinstance(value, dict):
            yield '{\n'
            for key in sorted(value):
                yield indent * nested_level
                yield '%r: ' % key
                for chunk in self._emit_literal(value[key], nested_level):
                    yield chunk
            yield indent * level + '}'
        elif isinstance(value, set):
            yield '{\n'
            for element in sorted(value):
                yield indent * nested_level
                for chunk in self._emit_literal(element, nested_level):
                    yield chunk
            yield indent * level + '}'
        else:
            yield repr(value)

        if level > 0:
            yield ','
        yield '\n'

    def _save_literal(self, path, value):
        with open(path, 'w') as f:
            for chunk in self._emit_literal(value):
                f.write(chunk)

    def _load_index(self):
        self._index = self._load_literal(self._index_path, dict())

    def _save_index(self):
        self._save_literal(self._index_path, self._index)

    def _hash_file(self, path, hashfunc):
        msg = hashfunc()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(self._BUFF_SIZE), b''):
                msg.update(chunk)
        return msg.hexdigest()

    def _copy_file(self, src, dest, overwrite=True):
        self._make_file_dir(dest)
        if overwrite or not os.path.exists(dest):
            shutil.copyfile(src, dest)

    def _get_path_in_pool(self, hash, filename):
        return os.path.join(hash[:2], hash[2:], filename)

    def _add_package_to_pool(self, path):
        hash = self._hash_file(path, hashlib.sha1)

        filename = os.path.basename(path)
        path_in_pool = self._get_path_in_pool(hash, filename)
        dest_path = os.path.join(self._pool_path, path_in_pool)
        self._copy_file(path, dest_path, overwrite=False)

        return (hash, filename)

    def _add_packages_to_pool(self, paths):
        filenames = dict()
        for path in paths:
            hash, filename = self._add_package_to_pool(path)
            filenames[hash] = filename
        return filenames

    def _add_package_to_index(self, dist, comp, hash, filename):
        hash_entry = self._index.setdefault(hash, dict())
        file_entry = hash_entry.setdefault(filename, set())
        file_entry.add('%s:%s' % (dist, comp))

    def _add_packages_to_index(self, dist, comp, filenames):
        for hash, filename in filenames.items():
            self._add_package_to_index(dist, comp, hash, filename)

    def add(self, dist, comp, paths):
        '''Adds packages to repository.'''
        filenames = self._add_packages_to_pool(paths)
        self._add_packages_to_index(dist, comp, filenames)

        # TODO: Remove.
        for filehash in self._index:
            print(self._get_deb_info(filehash))

    def _run_shell(self, args):
        child = subprocess.Popen(args,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

        out, err = child.communicate()

        if child.returncode:
            raise Error('subprocess returned %d: %s: %s' % (
                            child.returncode, ' '.join(args), err))

        return out

    # Returns full path to one (any) of packages in pool with a
    # given hash or None, if there are no such files.
    def _get_path_by_filehash(self, filehash):
        for filename in self._index[filehash]:
            path_in_pool = self._get_path_in_pool(filehash, filename)
            return os.path.join(self._pool_path, path_in_pool)

        return None

    # Retrieves info for packages with a given hash or None if
    # there are no such packages.
    def _get_deb_info(self, filehash):
        path = self._get_path_by_filehash(filehash)
        if path is None:
            return None

        # Run 'dpkg-deb' to list the control package fields.
        # TODO: We can run several processes simultaneously.
        output = self._run_shell(['dpkg-deb', '--field', path] +
                                  self.DEB_INFO_FIELDS)
        output = output.decode('utf-8')

        # Handle spliced lines.
        mark = '{makeapt_linebreak}'
        output = output.replace('\n ', mark + ' ')
        output = output.split('\n')
        output = [x.replace(mark, '\n') for x in output if x != '']

        deb_info = dict()
        for line in output:
            parts = line.split(':', maxsplit=1)
            if len(parts) < 2:
                raise Error('Unexpected control line %r in package %r.' % (
                                line, filename))

            field, value = tuple(parts)
            field = field.strip()
            value = value.strip()

            if field not in self.DEB_INFO_FIELDS:
                raise Error('Unknown control field %r in package %r.' % (
                                field, filename))

            if field in deb_info:
                raise Error('Duplicate control field %r in package %r.' % (
                                field, filename))

            deb_info[field] = value

        return deb_info


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
        parser.add_argument('component', help='Component name.')
        parser.add_argument('package', nargs='+',
                            help='The packages to add.')
        args = parser.parse_args(args)

        comp = args.component.split(':', maxsplit=1)
        if len(comp) == 1:
            comp.append('main')

        repo.add(dist=comp[0], comp=comp[1], paths=args.package)

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

        with Repository() as repo:
            handler(repo, command_parser, command_args)

    def run(self):
        self.execute_command_line(sys.argv[1:])


def main():
    driver = CommandLineDriver()
    driver.run()


if __name__ == '__main__':
    main()
