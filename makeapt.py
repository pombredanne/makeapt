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
    _ARCH_FIELD = 'Architecture'

    _MAKEAPT_FIELD_PREFIX = '__'
    _FILESIZE_FIELD = '%sfilesize' % _MAKEAPT_FIELD_PREFIX

    # We prefer these fields always be specified in this order.
    _DEB_INFO_FIELDS = [
        'Package',
        'Version',
        'Section',
        'Priority',
        _ARCH_FIELD,
        'Installed-Size',
        'Depends',
        'Maintainer',
        'Uploaders',
        'Homepage',
        'Description',
    ]

    # The name of the directory where we store .deb files.
    POOL_DIR_NAME = 'pool'

    # Canonical makeapt names of hash algorithms. APT
    # repositories use different names for the same hash
    #  algorithms, so for internal use we have to define their
    # canonical names.
    _CANONICAL_HASH_NAMES = {
        'md5': 'md5',
        'MD5Sum': 'md5',
        'MD5sum': 'md5',
        'sha1': 'sha1',
        'SHA1': 'sha1',
        'sha256': 'sha256',
        'SHA256': 'sha256',
        'sha512': 'sha512',
        'SHA512': 'sha512',
    }

    # The map of known hash algorithms. The keys are their
    # canonical names.
    _HASH_ALGOS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
    }

    # The hash algorithm used to find identical packages.
    _KEY_HASH_NAME = _CANONICAL_HASH_NAMES['sha1']

    # Buffer size for file I/O, in bytes.
    _BUFF_SIZE = 4096

    def __init__(self, path='.'):
        self._apt_path = path
        self._makeapt_path = os.path.join(self._apt_path, '.makeapt')
        self._index_path = os.path.join(self._makeapt_path, 'index')
        self._cache_path = os.path.join(self._makeapt_path, 'cache')
        self._pool_path = os.path.join(self._apt_path, self.POOL_DIR_NAME)
        self._dists_path = os.path.join(self._apt_path, 'dists')

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

    def _save_file(self, path, content):
        self._make_file_dir(path)
        with open(path, 'wb') as f:
            for chunk in content:
                if isinstance(chunk, str):
                    chunk = chunk.encode('ascii')
                f.write(chunk)

    def _gzip(self, path):
        # TODO: Can _run_shell() return a generator?
        # TODO: Should we do that with a Python library?
        yield self._run_shell(['gzip', '--keep', '--best', '--no-name',
                               '--stdout', path])

    def _bzip2(self, path):
        # TODO: Can _run_shell() return a generator?
        # TODO: Should we do that with a Python library?
        yield self._run_shell(['bzip2', '--keep', '--best',
                               '--stdout', path])

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

        # Fix the type of empty groups that 'literal_eval()'
        # reads as dict's and not set's.
        for filehash, filenames in index.items():
            for filename, groups in filenames.items():
                if isinstance(groups, dict):
                    assert not groups
                    groups = set()
                    filenames[filename] = groups

        self._index = index

    def _flush_index(self):
        self._save_literal(self._index_path, self._index)
        del self._index

    def _load_cache(self):
        self._cache = self._load_literal(self._cache_path, dict())

    def _flush_cache(self):
        self._save_literal(self._cache_path, self._cache)
        del self._cache

    # Hashes a given file with a set of specified algorithms.
    def _hash_file(self, path, hash_names):
        # Handle the case when only one algorithm is specified.
        if isinstance(hash_names, str):
            hash_name = hash_names
            return self._hash_file(path, {hash_name})[hash_name]

        # Initialize messages.
        msgs = {name: self._HASH_ALGOS[self._CANONICAL_HASH_NAMES[name]]()
                    for name in hash_names}

        # Read out the file by chunks and update messages.
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(self._BUFF_SIZE), b''):
                for hash_name, msg in msgs.items():
                    msg.update(chunk)

        return {hash_name: msg.hexdigest() for hash_name, msg in msgs.items()}

    def _copy_file(self, src, dest, overwrite=True):
        self._make_file_dir(dest)
        if overwrite or not os.path.exists(dest):
            shutil.copyfile(src, dest)

    def _link_or_copy_file(self, src, dest):
        # TODO: Use links by default and fallback to copies on an option.
        self._copy_file(src, dest)

    def _get_path_in_pool(self, file):
        filehash, filename = file
        return os.path.join(filehash[:2], filehash[2:], filename)

    def _add_package_to_pool(self, path):
        filehash = self._hash_file(path, self._KEY_HASH_NAME)
        filename = os.path.basename(path)
        file = filehash, filename
        path_in_pool = self._get_path_in_pool(file)
        dest_path = os.path.join(self._pool_path, path_in_pool)
        self._copy_file(path, dest_path, overwrite=False)
        return file

    def _add_packages_to_pool(self, paths):
        unique_paths = set(paths)
        return {self._add_package_to_pool(path) for path in unique_paths}

    def _add_package_to_index(self, filehash, filename):
        filenames = self._index.setdefault(filehash, dict())
        filenames.setdefault(filename, set())

    def _add_packages_to_index(self, files):
        for filehash, filename in files:
            self._add_package_to_index(filehash, filename)

    def add(self, paths):
        '''Adds packages to repository.'''
        files = self._add_packages_to_pool(paths)
        self._add_packages_to_index(files)
        return files

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
                yield (filehash, filename, groups)

    def _get_all_package_files(self):
        for filehash, filename, groups in self._get_all_packages():
            yield (filehash, filename)

    def _parse_package_spec(self, spec):
        excluding = spec.startswith('!')
        pattern = spec if not excluding else spec[1:]
        return (excluding, pattern)

    def _match_group(self, group, pattern):
        return fnmatch.fnmatch(group, pattern)

    def _match_groups(self, file, pattern, invert=False):
        # Consider name and hash of the file to be its implicit groups.
        filehash, filename = file
        groups = self._index[filehash][filename] | set(file)

        matches = any(self._match_group(group, pattern) for group in groups)
        if invert:
            matches = not matches
        return matches

    def _filter_packages(self, pattern, packages, invert=False):
        for file in packages:
            if self._match_groups(file, pattern, invert):
                yield file

    def _get_packages_by_specs(self, package_specs):
        packages = self._get_all_package_files()

        first = True
        for spec in package_specs:
            excluding, pattern = self._parse_package_spec(spec)

            # If the first specifier is including, use it instead of
            # considering all packages.
            if first and not excluding:
                packages = self._get_none_packages()

            if excluding:
                packages = self._filter_packages(pattern, packages,
                                                 invert=True)
            else:
                all_packages = self._get_all_package_files()
                packages = self._cat_generators(
                    packages,
                    self._filter_packages(pattern, all_packages))

            first = False

        return packages

    def add_to_group(self, group, files):
        for filehash, filename in files:
            self._index[filehash][filename].add(group)

    def group(self, group, package_specs):
        '''Makes packages part of a group.'''
        files = self._get_packages_by_specs(package_specs)
        self.add_to_group(group, files)

    def rmgroup(self, group, package_specs):
        '''Excludes packages from a group.'''
        for filehash, filename in self._get_packages_by_specs(package_specs):
            self._index[filehash][filename].discard(group)

    def ls(self, package_specs):
        '''Lists packages.'''
        return self._get_packages_by_specs(package_specs)

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
            path_in_pool = self._get_path_in_pool((filehash, filename))
            return os.path.join(self._pool_path, path_in_pool)

        return None

    def _is_key_hash_name(self, hash_name):
        return self._CANONICAL_HASH_NAMES[hash_name] == self._KEY_HASH_NAME

    def _get_hash_field_name(self, hash_name):
        return (self._MAKEAPT_FIELD_PREFIX +
                    self._CANONICAL_HASH_NAMES[hash_name])

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
                                  self._DEB_INFO_FIELDS)
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

            if field not in self._DEB_INFO_FIELDS:
                raise Error('Unknown control field %r in package %r.' % (
                                field, filename))

            if field in info:
                raise Error('Duplicate control field %r in package %r.' % (
                                field, filename))

            info[field] = value

        # TODO: Make sure all the necessary fields are in place.

        info[self._FILESIZE_FIELD] = os.path.getsize(path)

        hashes = self._hash_file(path, {'md5', 'sha1', 'sha256', 'sha512'})
        for hash_name, hash in hashes.items():
            if not self._is_key_hash_name(hash_name):
                field = self._get_hash_field_name(hash_name)
                info[field] = hash

        # Cache the results.
        self._cache[filehash] = info

        return info

    def _get_package_arch(self, filehash):
        return self._get_package_info(filehash)[self._ARCH_FIELD]

    def _get_package_hash(self, filehash, hash_name):
        if self._is_key_hash_name(hash_name):
            return filehash

        field = self._get_hash_field_name(hash_name)
        return self._get_package_info(filehash)[field]

    def _parse_distribution_component_group(self, group):
        parts = group.split(':')
        return tuple(parts) if len(parts) == 2 else None

    def _get_all_distribution_components(self):
        dists = dict()
        for filehash, filename, groups in self._get_all_packages():
            for group in groups:
                parts = self._parse_distribution_component_group(group)
                if not parts:
                    continue

                dist, component = parts
                components = dists.setdefault(dist, dict())
                archs = components.setdefault(component, dict())
                arch = self._get_package_arch(filehash)
                filenames = archs.setdefault(arch, dict())
                if filename in filenames:
                    raise Error('More than one package %r in component %r, '
                                'architecture %r.' % (
                                    filename, '%s:%s' % parts, arch))

                filenames[filename] = filehash

        return dists

    def _generate_package_index(self, file):
        # Emit the control fields from the deb file itself. Note that we want
        # them in this exactly order they come in the list.
        filehash, filename = file
        info = self._get_package_info(filehash)
        for field in self._DEB_INFO_FIELDS:
            if field in info:
                yield '%s: %s\n' % (field, info[field])

        # Emit additional fields.
        yield 'Filename: %s\n' % os.path.join(self.POOL_DIR_NAME,
                                              self._get_path_in_pool(file))

        yield 'Size: %u\n' % info[self._FILESIZE_FIELD]

        hash_algos = ['MD5sum',  # Note the lowercase 's' in 'MD5sum'.
                      'SHA1', 'SHA256', 'SHA512']
        for algo in hash_algos:
            yield '%s: %s\n' % (algo, self._get_package_hash(filehash, algo))

    def _generate_packages_index(self, files):
        for filename, filehash in files.items():
            for chunk in self._generate_package_index((filehash, filename)):
                yield chunk

    def _save_index_file(self, dist, path_in_dist, content, dist_index):
        path = os.path.join(self._dists_path, dist, path_in_dist)
        self._save_file(path, content)
        dist_index.add(path_in_dist)

        # Create by-hash copies.
        hash_names = ['MD5Sum',  # Note the uppercase 'S'.
                      'SHA256']
        for hash_name, hash in self._hash_file(path, hash_names).items():
            dir = os.path.dirname(path)
            dest_path = os.path.join(dir, 'by-hash', hash_name, hash)
            self._link_or_copy_file(path, dest_path)

        return path

    def _save_index(self, dist, path_in_dist, index, dist_index):
        path = self._save_index_file(dist, path_in_dist, index, dist_index)
        self._save_index_file(dist, path_in_dist + '.gz', self._gzip(path),
                              dist_index)
        self._save_index_file(dist, path_in_dist + '.bz2', self._bzip2(path),
                              dist_index)

    def _index_architecture(self, dist, component, arch, files, dist_index):
        path_in_dist = os.path.join(component, 'binary-%s' % arch, 'Packages')
        index = self._generate_packages_index(files)
        self._save_index(dist, path_in_dist, index, dist_index)

    def _index_distribution_component(self, dist, component, archs):
        dist_index = set()
        for arch, files in archs.items():
            self._index_architecture(dist, component, arch, files, dist_index)
        print(dist_index)

    def _index_distribution(self, dist, components):
        # Generate component-specific indexes.
        for component, archs in components.items():
            self._index_distribution_component(dist, component, archs)

    def index(self):
        '''Generates APT indexes.'''
        # TODO: Remove the whole 'dists' directory before re-indexing.
        dists = self._get_all_distribution_components()
        for dist, components in dists.items():
            self._index_distribution(dist, components)


class CommandLineDriver(object):
    def __init__(self):
        self._prog_name = os.path.basename(sys.argv[0])

        self.COMMANDS = {
            'add': (self.add, 'Add .deb files to repository.'),
            'group': (self.group, 'Make packages part of a group.'),
            'index': (self.index, 'Generate APT index files.'),
            'init': (self.init, 'Initialize APT repository.'),
            'ls': (self.ls, 'List packages.'),
            'rmgroup': (self.rmgroup, 'Excludes packages from a group.'),
        }

    def init(self, repo, parser, args):
        args = parser.parse_args(args)
        repo.init()

    def add(self, repo, parser, args):
        parser.add_argument('group', help='Group name.')
        parser.add_argument('path', nargs='+',
                            help='The package files to add.')
        args = parser.parse_args(args)
        files = repo.add(args.path)
        repo.add_to_group(args.group, files)

    def group(self, repo, parser, args):
        parser.add_argument('group', help='Group name.')
        parser.add_argument('package', nargs='*',
                            help='The packages to add.')
        args = parser.parse_args(args)
        repo.group(args.group, args.package)

    def rmgroup(self, repo, parser, args):
        parser.add_argument('group', help='Group name.')
        parser.add_argument('package', nargs='*',
                            help='The packages to exclude from the group.')
        args = parser.parse_args(args)
        repo.rmgroup(args.group, args.package)

    def ls(self, repo, parser, args):
        parser.add_argument('package', nargs='*',
                            help='The packages to list.')
        args = parser.parse_args(args)
        files = {(filename, filehash) for
                     filehash, filename in repo.ls(args.package)}
        for filename, filehash in sorted(files):
            print(filehash[:8], filename)

    def index(self, repo, parser, args):
        args = parser.parse_args(args)
        repo.index()

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
