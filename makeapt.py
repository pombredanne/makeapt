#!/usr/bin/env python3

import argparse
import ast
import fnmatch
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
        self._makeapt_path = os.path.join(self._apt_path, '.makeapt')
        self._index_path = os.path.join(self._makeapt_path, 'index')
        self._cache_path = os.path.join(self._makeapt_path, 'cache')
        self._pool_path = os.path.join(self._apt_path, 'pool')

    def __enter__(self):
        # TODO: Lock the repository.
        self._load_index()
        self._load_cache()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._flush_index()
        self._flush_cache()
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
        index = self._load_literal(self._index_path, dict())

        # Filename groups are not stored in index fields because they always
        # present. Here we add such groups and fix the type of empty groups
        # that 'literal_eval()' reads as dict's and not set's.
        for filehash, filenames in index.items():
            for filename, groups in filenames.items():
                if isinstance(groups, dict):
                    assert not groups
                    groups = set()
                    filenames[filename] = groups
                groups.add(filename)

        self._index = index

    def _flush_index(self):
        # Do not store groups that match filenames as they always
        # present and can be restored on load.
        for filehash, filenames in self._index.items():
            for filename, groups in filenames.items():
                groups.discard(filename)

        self._save_literal(self._index_path, self._index)
        del self._index

    def _load_cache(self):
        self._cache = self._load_literal(self._cache_path, dict())

    def _flush_cache(self):
        self._save_literal(self._cache_path, self._cache)
        del self._cache

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
        unique_paths = set(paths)
        files = dict()
        for path in unique_paths:
            filehash, filename = self._add_package_to_pool(path)
            files.setdefault(filehash, set()).add(filename)
        return files

    def _add_package_to_index(self, hash, filename):
        filenames = self._index.setdefault(hash, dict())
        groups = filenames.setdefault(filename, set())
        groups.add(filename)

    def _add_packages_to_index(self, files):
        for filehash, filenames in files.items():
            for filename in filenames:
                self._add_package_to_index(filehash, filename)

    def add(self, paths):
        '''Adds packages to repository.'''
        files = self._add_packages_to_pool(paths)
        self._add_packages_to_index(files)

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
    def _get_package_info(self, filehash):
        # See if the info is already cached.
        if filehash in self._cache:
            return self._cache[filehash]

        # Get the path to any of the files with the given hash,
        # if there are some.
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

        info = dict()
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

            if field in info:
                raise Error('Duplicate control field %r in package %r.' % (
                                field, filename))

            info[field] = value

        # Cache the results.
        self._cache[filehash] = info

        return info

    def _get_empty_generator(self):
        return (x for x in [])

    def _cat_generators(self, *generators):
        for g in generators:
            for i in g:
                yield i

    def _get_none_packages(self):
        return self._get_empty_generator()

    def _get_all_packages(self):
        for filehash, filenames in self._index.items():
            for filename, groups in filenames.items():
                yield (filehash, filename)

    def _parse_package_spec(self, spec):
        excluding = spec.startswith('!')
        pattern = spec if not excluding else spec[1:]
        return (excluding, pattern)

    def _match_group(self, group, pattern):
        return fnmatch.fnmatch(group, pattern)

    def _match_groups(self, groups, pattern):
        return any(self._match_group(group, pattern) for group in groups)

    def _match_packages(self, pattern, packages):
        for filehash, filename in packages:
            groups = self._index[filehash][filename]
            if self._match_groups(groups, pattern):
                yield (filehash, filename)

    def _apply_package_spec(self, excluding, pattern, packages):
        if excluding:
            return self._match_packages(pattern, packages)

        return self._cat_generators(
            packages,
            self._match_packages(pattern, self._get_all_packages()))

    def _enumerate_packages(self, package_specs):
        packages = self._get_all_packages()

        first = True
        for spec in package_specs:
            excluding, pattern = self._parse_package_spec(spec)

            # If the first specifier is including, use it instead of
            # considering all packages.
            if first and not excluding:
                packages = self._get_none_packages()

            packages = self._apply_package_spec(excluding, pattern, packages)

            first = False

        return packages

    def group(self, group, package_specs):
        '''Makes packages part of a group.'''
        for filehash, filename in self._enumerate_packages(package_specs):
            self._index[filehash][filename].add(group)


class CommandLineDriver(object):
    def __init__(self):
        self._prog_name = os.path.basename(sys.argv[0])

        self.COMMANDS = {
            'add': (self.add, 'Add .deb files to repository.'),
            'group': (self.group, 'Make packages part of a group.'),
            'init': (self.init, 'Initialize APT repository.'),
        }

    def init(self, repo, parser, args):
        args = parser.parse_args(args)
        repo.init()

    def add(self, repo, parser, args):
        parser.add_argument('path', nargs='+',
                            help='The package files to add.')
        args = parser.parse_args(args)
        repo.add(args.path)

    def group(self, repo, parser, args):
        parser.add_argument('group', help='Group name.')
        parser.add_argument('package', nargs='*',
                            help='The packages to add.')
        args = parser.parse_args(args)
        repo.group(args.group, args.package)

    def execute_command_line(self, args):
        parser = argparse.ArgumentParser(
            prog=self._prog_name,
            description='Debian APT repositories generator.')
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
