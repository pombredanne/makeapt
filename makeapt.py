#!/usr/bin/env python3

import argparse
import sys


class Error(Exception):
    pass


class CommandLineDriver(object):
    def __init__(self):
        self.COMMANDS = {
            'init': self.init,
        }

    def init(self, args):
        parser = argparse.ArgumentParser(
            description='Initialize APT repository.')
        args = parser.parse_args(args)
        print('OK')

    def execute_command_line(self, args):
        parser = argparse.ArgumentParser(
            description='Debian APT repositories generator')
        parser.add_argument('command', help='Command to run.')

        command = sys.argv[1:2]
        command_args = sys.argv[2:]

        args = parser.parse_args(command)
        if args.command not in self.COMMANDS:
            raise Error('Unknown command %r.' % args.command)

        self.COMMANDS[args.command](command_args)

    def run(self):
        self.execute_command_line(sys.argv[1:])


if __name__ == '__main__':
    driver = CommandLineDriver()
    driver.run()
