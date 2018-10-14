#!/usr/bin/env python3

import argparse
import ast
import datetime
import fnmatch
import hashlib
import os
import shutil
import subprocess
import sys


class Error(Exception):
    pass


class _Path(object):
    def __init__(self, path=[]):
        if not path:
            self._comps = []
        elif isinstance(path, _Path):
            self._comps = path._comps
        elif isinstance(path, list):
            self._comps = path
        else:
            assert isinstance(path, str), repr(path)
            self._comps = [path]

    def get_as_string(self):
        return os.path.join(*tuple(self._comps))

    def __add__(self, other):
        return _Path(self._comps + _Path(other)._comps)

    def get_dirname(self):
        return _Path(self._comps[:-1])

    def get_basename(self):
        return self._comps[-1]

    def add_extension(self, ext):
        new_basename = self.get_basename() + ext
        return self.get_dirname() + new_basename

    def __iter__(self):
        for comp in self._comps:
            yield comp


class _Package(object):
    def __init__(self, filehash, filename):
        self._filehash = filehash
        self._filename = filename

    def get_filehash(self):
        return self._filehash

    def get_filename(self):
        return self._filename


class _RepositoryIndex(object):
    _index = dict()

    def add_file_path(self, path):
        i = self._index
        for comp in path.get_dirname():
            i = i.setdefault(comp, dict())
        i[path.get_basename()] = None

    def get(self):
        index_copy = dict(self._index)
        return index_copy


class _ComponentArch(object):
    def __init__(self, arch_id, component):
        self._id = arch_id
        self._component = component

    def get_id(self):
        return self._id

    def get_component(self):
        return self._component

    def get_component_id(self):
        return self._component.get_id()

    def get_distribution(self):
        return self._component.get_distribution()

    def get_packages(self):
        return self._component.get_packages_in_arch(self)

    def get_path_in_distribution(self):
        return self._component.get_path_in_distribution()


class _Component(object):
    def __init__(self, component_id, dist):
        self._id = component_id
        self._dist = dist

    def get_id(self):
        return self._id

    def get_distribution(self):
        return self._dist

    def get_archs(self):
        return self._dist.get_archs_in_component(self)

    def get_packages_in_arch(self, arch):
        assert isinstance(arch, _ComponentArch)
        assert arch.get_component() is self
        return self._dist.get_packages_in_component_arch(arch)

    def get_path_in_distribution(self):
        return _Path([self._id])


class _DistributionArch(object):
    def __init__(self, arch_id, dist):
        self._id = arch_id
        self._dist = dist

    def get_id(self):
        return self._id

    def get_distribution(self):
        return self._dist

    def get_packages(self):
        return self._dist.get_packages_in_arch(self)

    def get_path_in_distribution(self):
        return _Path()


class _DistributionIndex(object):
    def __init__(self):
        self._index = dict()

    def get(self):
        return self._index

    def add(self, path, hashes, filesize):
        assert path not in self._index
        self._index[path] = hashes, filesize


class _Distribution(object):
    def __init__(self, dist_id, repo_index):
        self._id = dist_id
        self._index = _DistributionIndex()
        self._repo_index = repo_index
        self._packages = dict()

    def get_id(self):
        return self._id

    def get_index(self):
        return self._index

    def get_repository_index(self):
        return self._repo_index

    def add_package(self, component_id, arch_id, package):
        key = component_id, arch_id
        filenames = self._packages.setdefault(key, dict())
        filename = package.get_filename()
        if filename in filenames:
            full_component_id = '%s:%s' % (self._dist_id, component_id)
            raise Error('More than one package %r in component %r, '
                        'architecture %r.' % (filename, full_component_id,
                                              arch_id))

        filenames[filename] = package.get_filehash()

    # Returns components of this distribution.
    def get_components(self):
        ids = {component_id for component_id, arch_id in self._packages}
        for id in ids:
            yield _Component(id, self)

    # Returns architectures of this distribution's component.
    def get_archs_in_component(self, component):
        assert component.get_distribution() is self
        component_id = component.get_id()
        ids = {arch_id for comp_id, arch_id in self._packages
                   if comp_id == component_id}
        for id in ids:
            yield _ComponentArch(id, component)

    # Returns architectures of all components in this distribution.
    def get_archs_in_all_components(self):
        for component in self.get_components():
            for arch in component.get_archs():
                yield arch

    # Returns architectures of this distribution.
    def get_archs(self):
        ids = {arch_id for component_id, arch_id in self._packages}
        for id in ids:
            yield _DistributionArch(id, self)

    # Returns packages for specific component architecture in
    # this distribution.
    def get_packages_in_component_arch(self, arch):
        assert isinstance(arch, _ComponentArch)
        assert arch.get_distribution() is self
        target_key = arch.get_component_id(), arch.get_id()
        for key, filenames in self._packages.items():
            if key == target_key:
                for filename, filehash in filenames.items():
                    yield _Package(filehash, filename)

    # Returns packages for a specific architecture in this distribution.
    def get_packages_in_arch(self, arch):
        assert isinstance(arch, _DistributionArch)
        assert arch.get_distribution() is self
        target_arch_id = arch.get_id()
        for (component_id, arch_id), filenames in self._packages.items():
            if arch_id == target_arch_id:
                for filename, filehash in filenames.items():
                    yield _Package(filehash, filename)


class Repository(object):
    _DEFAULT_CONFIG = {
        'origin': 'Default Origin',
        'label': 'Default Label',
        'gpg_key_id': 'none',
    }

    _PACKAGE_FIELD = 'Package'
    _SECTION_FIELD = 'Section'
    _ARCH_FIELD = 'Architecture'

    _MAKEAPT_FIELD_PREFIX = '__'
    _CONTENTS_FIELD = '%scontents' % _MAKEAPT_FIELD_PREFIX
    _FILESIZE_FIELD = '%sfilesize' % _MAKEAPT_FIELD_PREFIX

    # We prefer these fields always be specified in this order.
    _DEB_INFO_FIELDS = [
        _PACKAGE_FIELD,
        'Version',
        _SECTION_FIELD,
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

    # The directory where we store distribution index files.
    DISTS_DIR = _Path('dists')

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

    # The names of hashes used in main distribution indexes. Come
    # in order we want them in the index files.
    _DISTRIBUTION_INDEX_HASH_NAMES = [
        'MD5Sum',  # Note the uppercase 'S' in 'MD5Sum'.
        'SHA1', 'SHA256']

    # Buffer size for file I/O, in bytes.
    _BUFF_SIZE = 4096

    def __init__(self, path=''):
        self._apt_path = _Path(path)
        self._makeapt_path = self._apt_path + '.makeapt'
        self._config_path = self._makeapt_path + 'config'
        self._index_path = self._makeapt_path + 'index'
        self._cache_path = self._makeapt_path + 'cache'
        self._pool_path = self._apt_path + self.POOL_DIR_NAME

    def __enter__(self):
        # TODO: Lock the repository.
        self._load_config()
        self._load_index()
        self._load_cache()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._flush_index()
        self._flush_cache()
        self._flush_config()
        # TODO: Unlock the repository.

    def get_config(self):
        # Always return a copy of the actual config.
        config_copy = dict(self._config)
        return config_copy

    def get_config_field(self, field):
        config = self.get_config()
        return config[field]

    def set_config_field(self, field, value):
        self._config[field] = value

    def _make_dir(self, path):
        path_string = path.get_as_string()
        if not os.path.exists(path_string):
            os.makedirs(path_string)

    def _make_file_dir(self, path):
        self._make_dir(path.get_dirname())

    def _save_file(self, path, content):
        self._make_file_dir(path)
        with open(path.get_as_string(), 'wb') as f:
            for chunk in content:
                if isinstance(chunk, str):
                    chunk = chunk.encode('utf-8')
                f.write(chunk)

    def _gzip(self, path):
        # TODO: Can _run_shell() return a generator?
        # TODO: Should we do that with a Python library?
        yield self._run_shell(['gzip', '--keep', '--best', '--no-name',
                               '--stdout', path.get_as_string()])

    def _bzip2(self, path):
        # TODO: Can _run_shell() return a generator?
        # TODO: Should we do that with a Python library?
        yield self._run_shell(['bzip2', '--keep', '--best',
                               '--stdout', path.get_as_string()])

    def init(self):
        '''Initializes APT repository.'''
        self._make_dir(self._makeapt_path)
        self._make_dir(self._pool_path)
        # TODO: Should we make the 'dists' directory?

    def _load_literal(self, path, default):
        try:
            with open(path.get_as_string(), 'r') as f:
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
        with open(path.get_as_string(), 'w') as f:
            for chunk in self._emit_literal(value):
                f.write(chunk)

    def _load_config(self):
        default_config_copy = dict(self._DEFAULT_CONFIG)
        config = self._load_literal(self._config_path, default_config_copy)

        # Make sure all fields are in place.
        for field, default_value in self._DEFAULT_CONFIG.items():
            if field not in config:
                config[field] = default_value

        self._config = config

    def _flush_config(self):
        self._save_literal(self._config_path, self._config)
        del self._config

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
        with open(path.get_as_string(), 'rb') as f:
            for chunk in iter(lambda: f.read(self._BUFF_SIZE), b''):
                for hash_name, msg in msgs.items():
                    msg.update(chunk)

        return {hash_name: msg.hexdigest() for hash_name, msg in msgs.items()}

    def _copy_file(self, src, dest, overwrite=True):
        self._make_file_dir(dest)

        dest_string = dest.get_as_string()
        if overwrite or not os.path.exists(dest_string):
            shutil.copyfile(src.get_as_string(), dest_string)

    def _link_or_copy_file(self, src, dest):
        # TODO: Use links by default and fallback to copies on an option.
        self._copy_file(src, dest)

    def _get_path_in_pool(self, package):
        filehash = package.get_filehash()
        filename = package.get_filename()
        return _Path([filehash[:2], filehash[2:], filename])

    def _get_full_package_path(self, package):
        return self._pool_path + self._get_path_in_pool(package)

    def _add_package_to_pool(self, path):
        filehash = self._hash_file(_Path([path]), self._KEY_HASH_NAME)
        filename = os.path.basename(path)
        package = _Package(filehash, filename)
        path_in_pool = self._get_path_in_pool(package)
        dest_path = self._pool_path + path_in_pool
        self._copy_file(_Path([path]), dest_path, overwrite=False)
        return package

    def _add_packages_to_pool(self, paths):
        unique_paths = set(paths)
        return {self._add_package_to_pool(path) for path in unique_paths}

    def _add_package_to_index(self, package):
        filenames = self._index.setdefault(package.get_filehash(), dict())
        filenames.setdefault(package.get_filename(), set())

    def _add_packages_to_index(self, packages):
        for package in packages:
            self._add_package_to_index(package)

    def add(self, paths):
        '''Adds packages to repository.'''
        packages = self._add_packages_to_pool(paths)
        self._add_packages_to_index(packages)
        return packages

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
                yield _Package(filehash, filename), groups

    def _get_all_package_files(self):
        for package, groups in self._get_all_packages():
            yield package

    def _get_package_files_by_hash(self, filehash):
        for filename in self._index[filehash]:
            yield _Package(filehash, filename)

    def _get_any_package_file_by_hash(self, filehash):
        for package in self._get_package_files_by_hash(filehash):
            return package
        return None

    def _parse_package_spec(self, spec):
        excluding = spec.startswith('!')
        pattern = spec if not excluding else spec[1:]
        return (excluding, pattern)

    def _match_group(self, group, pattern):
        return fnmatch.fnmatch(group, pattern)

    def _get_package_groups(self, package):
        filehash = package.get_filehash()
        filename = package.get_filename()
        return self._index[filehash][filename]

    def _match_groups(self, package, pattern, invert=False):
        # Consider name and hash of the file to be its implicit groups.
        groups = (self._get_package_groups(package) |
                      {package.get_filehash(), package.get_filename()})

        matches = any(self._match_group(group, pattern) for group in groups)
        if invert:
            matches = not matches
        return matches

    def _filter_packages(self, pattern, packages, invert=False):
        for package in packages:
            if self._match_groups(package, pattern, invert):
                yield package

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

    def add_to_group(self, group, packages):
        for package in packages:
            self._get_package_groups(package).add(group)

    def group(self, group, package_specs):
        '''Makes packages part of a group.'''
        packages = self._get_packages_by_specs(package_specs)
        self.add_to_group(group, packages)

    def rmgroup(self, group, package_specs):
        '''Excludes packages from a group.'''
        for package in self._get_packages_by_specs(package_specs):
            self._get_package_groups(package).discard(group)

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

    def _is_key_hash_name(self, hash_name):
        return self._CANONICAL_HASH_NAMES[hash_name] == self._KEY_HASH_NAME

    def _get_hash_field_name(self, hash_name):
        return (self._MAKEAPT_FIELD_PREFIX +
                    self._CANONICAL_HASH_NAMES[hash_name])

    def _get_deb_control_info(self, package):
        # Run 'dpkg-deb' to list the control package fields.
        # TODO: We can run several processes simultaneously.
        path = self._get_full_package_path(package)
        output = self._run_shell(['dpkg-deb',
                                  '--field', path.get_as_string()] +
                                  self._DEB_INFO_FIELDS)
        output = output.decode('utf-8')

        # Handle spliced lines.
        mark = '{makeapt_linebreak}'
        output = output.replace('\n ', mark + ' ')
        output = output.split('\n')
        output = [x.replace(mark, '\n') for x in output if x != '']

        filename = package.get_filename()
        info = dict()
        for line in output:
            parts = line.split(':', maxsplit=1)
            if len(parts) != 2:
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

        return info

    def _get_deb_contents(self, package):
        path = self._get_full_package_path(package)
        out = self._run_shell(['dpkg-deb', '--contents', path.get_as_string()])
        out = out.decode('utf-8').split('\n')

        # Remove empty lines.
        out = [line for line in out if line]

        # Get only filenames.
        out = [line.split()[5] for line in out]

        # Strip directories.
        out = [line for line in out if not line.endswith('/')]

        # Strip './' in the beginning of paths.
        out = [line[2:] if line.startswith('./') else line for line in out]

        return set(out)

    # Retrieves info for packages with a given hash or None if
    # there are no such packages.
    def _get_package_info(self, filehash):
        # See if the info is already cached.
        if filehash in self._cache:
            return self._cache[filehash]

        # Get any package with the given hash, if there are some.
        package = self._get_any_package_file_by_hash(filehash)
        if package is None:
            return None

        info = self._get_deb_control_info(package)

        info[self._CONTENTS_FIELD] = self._get_deb_contents(package)

        path = self._get_full_package_path(package)
        info[self._FILESIZE_FIELD] = os.path.getsize(path.get_as_string())

        hashes = self._hash_file(path, {'md5', 'sha1', 'sha256', 'sha512'})
        for hash_name, hash in hashes.items():
            if not self._is_key_hash_name(hash_name):
                field = self._get_hash_field_name(hash_name)
                info[field] = hash

        # Cache the results.
        self._cache[filehash] = info

        return info

    def _get_package_arch(self, filehash):
        package_info = self._get_package_info(filehash)
        return package_info[self._ARCH_FIELD]

    def _get_package_hash(self, filehash, hash_name):
        if self._is_key_hash_name(hash_name):
            return filehash

        package_info = self._get_package_info(filehash)
        field = self._get_hash_field_name(hash_name)
        return package_info[field]

    def _parse_distribution_component_group(self, group):
        ids = group.split(':')
        return tuple(ids) if len(ids) == 2 else None

    def _get_distributions(self, repo_index):
        dists = dict()
        for package, groups in self._get_all_packages():
            for group in groups:
                ids = self._parse_distribution_component_group(group)
                if not ids:
                    continue

                dist_id, component_id = ids
                if dist_id in dists:
                    dist = dists[dist_id]
                else:
                    dist = _Distribution(dist_id, repo_index)
                    dists[dist_id] = dist

                arch_id = self._get_package_arch(package.get_filehash())
                dist.add_package(component_id, arch_id, package)

        for dist_id, dist in dists.items():
            yield dist

    def _generate_package_index(self, package):
        # Emit the control fields from the deb file itself. Note that we want
        # them in this exactly order they come in the list.
        info = self._get_package_info(package.get_filehash())
        for field in self._DEB_INFO_FIELDS:
            if field in info:
                yield '%s: %s\n' % (field, info[field])

        # Emit additional fields.
        filename_field = (_Path([self.POOL_DIR_NAME]) +
                              self._get_path_in_pool(package)).get_as_string()
        yield 'Filename: %s\n' % filename_field

        yield 'Size: %u\n' % info[self._FILESIZE_FIELD]

        hash_algos = ['MD5sum',  # Note the lowercase 's' in 'MD5sum'.
                      'SHA1', 'SHA256', 'SHA512']
        for algo in hash_algos:
            hash = self._get_package_hash(package.get_filehash(), algo)
            yield '%s: %s\n' % (algo, hash)

    def _generate_packages_index(self, packages):
        for package in packages:
            for chunk in self._generate_package_index(package):
                yield chunk

    def _save_apt_file(self, path, content, repo_index, is_temporary=False):
        full_path = self._apt_path + path
        self._save_file(full_path, content)
        if not is_temporary and repo_index:
            repo_index.add_file_path(path)
        return full_path

    def _save_index_file(self, dist, path_in_dist, content,
                         is_temporary=False):
        path = self._save_apt_file(
            self.DISTS_DIR + dist.get_id() + path_in_dist,
            content, dist.get_repository_index(),
            is_temporary=is_temporary)

        # Remember the hashes and the size of the resulting file.
        path_in_dist_string = path_in_dist.get_as_string()
        hashes = self._hash_file(path, self._DISTRIBUTION_INDEX_HASH_NAMES)
        filesize = os.path.getsize(path.get_as_string())
        dist.get_index().add(path_in_dist_string, hashes, filesize)

        # Create by-hash copies.
        if not is_temporary:
            hash_names = ['MD5Sum',  # Note the uppercase 'S'.
                          'SHA256']
            for hash_name, hash in self._hash_file(path, hash_names).items():
                dir = path.get_dirname()
                dest_path = dir + 'by-hash' + hash_name + hash
                self._link_or_copy_file(path, dest_path)

        return path

    def _save_index(self, dist, path_in_dist, index,
                    create_compressed_versions=True,
                    keep_uncompressed_version=True):
        path = self._save_index_file(
            dist, path_in_dist, index,
            is_temporary=not keep_uncompressed_version)
        if create_compressed_versions:
            self._save_index_file(dist, path_in_dist.add_extension('.gz'),
                                  self._gzip(path))
            self._save_index_file(dist, path_in_dist.add_extension('.bz2'),
                                  self._bzip2(path))

        # Note that the uncompressed version goes to the
        # distribution index even if it doesn't present in the
        # repository.
        if not keep_uncompressed_version:
            os.remove(path.get_as_string())

    def _generate_release_index(self, arch):
        yield 'Origin: %s\n' % self._config['origin']
        yield 'Label: %s\n' % self._config['label']
        yield 'Component: %s\n' % arch.get_component().get_id()
        yield 'Architecture: %s\n' % arch.get_id()
        yield 'Acquire-By-Hash: yes\n'  # TODO: Should be configurable.

    def _generate_contents_index(self, packages):
        index = dict()
        for package in packages:
            package_info = self._get_package_info(package.get_filehash())
            location = '%s/%s' % (package_info[self._SECTION_FIELD],
                                  package_info[self._PACKAGE_FIELD])

            # TODO: Debian documentation reads so that use of the
            # area name part is deprecated. Despite that, Debian
            # archvies still seem to be using them. So do we.
            # https://wiki.debian.org/DebianRepository/Format?action=show&redirect=RepositoryFormat#A.22Contents.22_indices
            # http://ftp.debian.org/debian/dists/stable/non-free/Contents-i386.gz
            # location = '/'.join(location.split('/')[1:])

            contents = package_info[self._CONTENTS_FIELD]
            for contents_filename in contents:
                index.setdefault(contents_filename, set()).add(location)

        if not index:
            return

        yield 'FILE LOCATION\n'
        for contents_filename in sorted(index):
            locations = ','.join(sorted(index[contents_filename]))
            yield '%s %s\n' % (contents_filename, locations)

    def _save_contents_index(self, arch):
        # Note that according to the Debian specification, we
        # have to add the uncompressed version of the index to
        # the release index regardless of whether we store the
        # first. This way apt clients can check indexes both
        # before and after decompression.
        contents_index = self._generate_contents_index(arch.get_packages())
        path = arch.get_path_in_distribution() + 'Contents-%s' % arch.get_id()
        self._save_index(arch.get_distribution(), path, contents_index,
                         keep_uncompressed_version=False)

    def _index_architecture(self, arch):
        # Generate packages index.
        dir_in_dist = _Path([arch.get_component().get_id(),
                             'binary-%s' % arch.get_id()])
        dist = arch.get_distribution()
        self._save_index(dist, dir_in_dist + 'Packages',
                         self._generate_packages_index(arch.get_packages()))

        # Generate release index.
        release_index = self._generate_release_index(arch)
        self._save_index(dist, dir_in_dist + 'Release',
                         release_index, create_compressed_versions=False)

        # Generate component contents index.
        self._save_contents_index(arch)

    def _index_distribution_component(self, component):
        for arch in component.get_archs():
            self._index_architecture(arch)

    def _generate_distribution_index(self, dist):
        yield 'Origin: %s\n' % self._config['origin']
        yield 'Label: %s\n' % self._config['label']
        yield 'Suite: %s\n' % dist.get_id()
        yield 'Codename: %s\n' % dist.get_id()

        now = datetime.datetime.utcnow()
        yield 'Date: %s\n' % now.strftime('%a, %d %b %Y %H:%M:%S +0000')

        components = (component.get_id()
                          for component in dist.get_components())
        yield 'Components: %s\n' % ' '.join(sorted(components))

        archs = (arch.get_id() for arch in dist.get_archs())
        yield 'Architectures: %s\n' % ' '.join(sorted(archs))

        yield 'Acquire-By-Hash: yes\n'

        dist_index = dist.get_index().get()
        for hash_name in self._DISTRIBUTION_INDEX_HASH_NAMES:
            yield '%s:\n' % hash_name
            for index in sorted(dist_index):
                hashes, filesize = dist_index[index]
                yield ' %s %s %s\n' % (hashes[hash_name], filesize, index)

    def _index_distribution(self, dist):
        # Generate component-specific indexes.
        for component in dist.get_components():
            self._index_distribution_component(component)

        # Generate distribution contents indexes.
        for arch in dist.get_archs():
            self._save_contents_index(arch)

        # Generate distribution index.
        index = self._generate_distribution_index(dist)
        index_path = self.DISTS_DIR + dist.get_id() + 'Release'
        full_index_path = self._save_apt_file(index_path, index,
                                              dist.get_repository_index())

        # Sign the index.
        gpg_key_id = self._config['gpg_key_id']
        if gpg_key_id != 'none':
            digest_algo = 'SHA256'  # Should be configurable?
            full_index_gpg_path = full_index_path.add_extension('.gpg')
            self._run_shell(['gpg', '--armor', '--detach-sign', '--sign',
                             '--default-key', gpg_key_id,
                             '--personal-digest-preferences', digest_algo,
                             '--output', full_index_gpg_path.get_as_string(),
                             '--yes', index_path.get_as_string()])

            full_inrelease_path = full_index_path.get_dirname() + 'InRelease'
            self._run_shell(['gpg', '--armor', '--clearsign', '--sign',
                             '--default-key', gpg_key_id,
                             '--personal-digest-preferences', digest_algo,
                             '--output', full_inrelease_path.get_as_string(),
                             '--yes', index_path.get_as_string()])

    def index(self, repo_index=None):
        '''Generates APT indexes.'''
        # TODO: Remove the whole 'dists' directory before re-indexing.
        for dist in self._get_distributions(repo_index):
            self._index_distribution(dist)

        # Add all packages in the pool to the repository index.
        if repo_index:
            for package in self._get_all_package_files():
                path = self._get_full_package_path(package)
                repo_index.add_file_path(path)


class CommandLineDriver(object):
    def __init__(self):
        self._prog_name = os.path.basename(sys.argv[0])

        self.COMMANDS = {
            'config': (self.config, 'List or set configuration fields.'),
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
        packages = repo.add(args.path)
        repo.add_to_group(args.group, packages)

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
        files = {(package.get_filename(), package.get_filehash()) for
                     package in repo.ls(args.package)}
        for filename, filehash in sorted(files):
            print(filehash[:8], filename)

    def index(self, repo, parser, args):
        args = parser.parse_args(args)
        repo.index()

    def _print_config_field(self, field, value):
        print('%s=%s' % (field, value))

    def config(self, repo, parser, args):
        parser.add_argument('field', nargs='?',
                            help='The field to display or set.')
        parser.add_argument('value', nargs='?',
                            help='The new value to set to the field.')
        args = parser.parse_args(args)
        if args.field and args.value:
            repo.set_config_field(args.field, args.value)
        elif args.field:
            value = repo.get_config_field(args.field)
            self._print_config_field(args.field, value)
        else:
            config = repo.get_config()
            for field in sorted(config):
                self._print_config_field(field, config[field])

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
