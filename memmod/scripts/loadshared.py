#!/bin/python3
from memmod import Process

import argparse
import sys
import os


def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument('-n', '--name', help='Select process by name', type=str)
    arguments.add_argument('-p', '--pid', help='Select process by pid', type=int)

    args, files = arguments.parse_known_args()
    args = vars(args)

    if not files:
        print('loadshared.py: error: Missing arguments to shared library')
        sys.exit()

    # open process by name or it's process id
    if not args['name'] and not args['pid']:
        print('loadshared.py: error: the following arguments are required: -p/--pid or -n/--name')
        sys.exit()

    proc = Process(pid=args['pid'], name=args['name'])
    print('Opend process with pid %d' % proc.pid)

    # Load shared libraries
    for path in files:
        print('Loading `%s`: %d' % (os.path.realpath(path), proc.load_shaderd_library(path)))

