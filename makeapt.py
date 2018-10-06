#!/usr/bin/env python3

import argparse
import os
import sys


class Error(Exception):
    pass


class Repository(object):
    def __init__(self, path=''):
        self._apt_path = path
        self._makeapt_path = os.path.join(self._apt_path, '.makeapt')

    def init(self):
        '''Initializes APT repository.'''
        os.makedirs(self._makeapt_path)


class CommandLineDriver(object):
    def __init__(self):
        self.COMMANDS = {
            'init': self.init,
        }

    def init(self, repo, args):
        parser = argparse.ArgumentParser(
            description='Initialize APT repository.')
        args = parser.parse_args(args)
        repo.init()

    def execute_command_line(self, args):
        parser = argparse.ArgumentParser(
            description='Debian APT repositories generator')
        parser.add_argument('command', help='The command to run.')

        command = sys.argv[1:2]
        command_args = sys.argv[2:]

        args = parser.parse_args(command)
        if args.command not in self.COMMANDS:
            raise Error('Unknown command %r.' % args.command)

        repo = Repository()
        self.COMMANDS[args.command](repo, command_args)

    def run(self):
        self.execute_command_line(sys.argv[1:])


def main():
    driver = CommandLineDriver()
    driver.run()


if __name__ == '__main__':
    main()
