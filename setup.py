#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import setuptools

setuptools.setup(
    name='makeapt',
    version='1.0a0',
    packages=[],
    scripts=['makeapt.py'],
    install_requires=[
        'argparse',
    ],
    description='Debian APT repositories generator',
    author='Ivan Kosarev',
    author_email='ivan@kosarev.info',
    license='MIT',
    keywords='debian apt repository',
    url='https://github.com/kosarev/makeapt',
    entry_points={
        'console_scripts': [
            'makeapt = makeapt:main',
        ],
    },
    # TODO: test_suite='tests',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development',
        'Topic :: Software Development :: Build Tools',
        'Topic :: System :: Archiving :: Packaging',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Software Distribution',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
)
