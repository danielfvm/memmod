#!/bin/python3

from memmod.process import ScanMode, ScanResult
from memmod import Process, Module

import argparse
import sys


def find_static_pointers(proc: Process, module: Module, heap: Module) -> list[ScanResult]:
    return proc.scan(ScanMode.INSIDE, module.start, module.end, heap.start, heap.end)


def list_to_dict(pointers: list[ScanResult]) -> dict[int, int]:
    _pointers = {}
    for ptr in pointers:
        if ptr.value in _pointers:
            _pointers[ptr.value].append(ptr.address)
        else:
            _pointers[ptr.value] = [ptr.address]
    return _pointers


def find_pointer_path(static_pointers: dict, dynamic_pointers: dict, address: int, bounds: int, _history=[], _nested=4) -> list[list[int]]:
    if _nested <= 0:
        return []

    results = []
    for offset in range(bounds):
        ptr_address = address - offset
        if ptr_address in static_pointers:
            for ptr in static_pointers[ptr_address]:
                results.append([ptr, offset] + _history)

        if ptr_address in dynamic_pointers:
            for ptr in dynamic_pointers[ptr_address]:
                results.extend(find_pointer_path(static_pointers, dynamic_pointers, ptr, bounds, [offset] + _history, _nested-1))
    return results


def hexvalue(x):
    return int(x, 0)


def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument('-n', '--name', help='Select process by name', type=str)
    arguments.add_argument('-p', '--pid', help='Select process by pid', type=int)
    arguments.add_argument('-a', '--address', help='Use the static pointers to search for a path to this address', type=hexvalue)
    arguments.add_argument('-s', '--save', help='Specify the file to save the results in.', type=str)
    arguments.add_argument('-m', '--module', help='Specify modules to scan for static pointers, default: all', type=str, default=None, nargs='+')
    arguments.add_argument('-r', '--range', help='The range specifies the maximum offset to the address, default: 0x200', type=hexvalue, default=0x200)
    arguments.add_argument('-d', '--depth', help='How long a path can be, default: 3', type=hexvalue, default=3)
    arguments.add_argument('-sf', '--staticfile', help='Select a file with static pointers', type=str)

    args, _ = arguments.parse_known_args()
    args = vars(args)

    # open process by name or it's process id
    if not args['name'] and not args['pid']:
        print('pointerscanner.py: error: the following arguments are required: -p/--pid or -n/--name')
        sys.exit()

    proc = Process(pid=args['pid'], name=args['name'])
    print('Opend process with pid %d' % proc.pid)

    # get heap module
    heap = proc.find_module('[heap]')
    if not heap:
        print('pointerscanner.py: error: Failed to open heap module.')
        sys.exit()

    # search static pointers
    static_pointers: list[ScanResult] = []

    if args['staticfile']:
        print('\n=== Start loading static pointers from file ===')
        with open(args['staticfile'], 'r') as file:
            for line in file.readlines():
                data = line.split('+')
                module = proc.find_module(data[0])

                if module == None:
                    print("Failed to find module", data[0])
                    continue

                offset = int(data[1], 16)
                data = proc.read(module.start+offset, 8)
                value = int.from_bytes(data, sys.byteorder)

                if heap.contains_address(value):
                    static_pointers.append(ScanResult(heap.start+offset, data))

        print('Loaded static_pointers:', len(static_pointers))
    else:
        print('\n=== Start searching for static pointers ===')
        if not args['module']:
            for mod in proc.modules:
                if '/dev/' in mod.path or '/memfd/' in mod.path:
                    continue
                if '(deleted)' in mod.path or ('[' in mod.path and ']' in mod.path):
                    continue
                if mod.mode != 'rw-p':
                    continue
                if len(mod.path) <= 0:
                    continue

                results = find_static_pointers(proc, mod, heap)
                static_pointers.extend(results)
                print('%s: %d' % (mod.path, len(results)))
        else:
            for name in args['module']:
                mod = proc.find_module(name, mode='rw-p')
                if not mod:
                    print('pointerscanner.py: error: Failed to locate module:', name)
                else:
                    results = find_static_pointers(proc, mod, heap)
                    static_pointers.extend(results)
                    print('%s: %d' % (mod.path, len(results)))

        print('Total static_pointers found:', len(static_pointers))
        if args['save'] is not None:
            file_name = 'static.' + args['save'].strip()
            with open(file_name, 'w+') as f:
                for ptr in static_pointers:
                    mod = proc.find_module_with_address(ptr)
                    assert mod != None, "Invalid address for static pointer!"
                    base = proc.find_module(mod.path)
                    assert base != None, "Invalid address for static pointer!"
                    f.write('%s + 0x%x\n' % (base.path, ptr.address-base.start))
            print('Saved to file:', file_name)


    # search paths to address
    if args['address'] is not None:

        print('\n=== Start searching for dynamic pointers ===')
        dynamic_pointers = proc.scan(ScanMode.INSIDE, heap.start, heap.end, heap.start, heap.end)
        print("Total dynamic pointer found:", len(dynamic_pointers))

        print('\n=== Start searching for pointer paths ===')
        results = find_pointer_path(list_to_dict(static_pointers), list_to_dict(dynamic_pointers), int(args['address']), int(args['range']), _nested=int(args['depth']))

        text = ''
        for res in results:
            mod = proc.find_module_with_address(res[0])
            assert mod != None, "Invalid address for static pointer!"
            base = proc.find_module(mod.path)
            assert base != None, "Invalid address for static pointer!"

            text += '%s+%-10x ' % (mod.path, res[0]-base.start)
            for offset in res[1:]:
                text += '%-6x' % offset
            text += '\n'
        print(text)

        print('Total paths found:', len(results))
        if args['save'] is not None:
            file_name = 'path.' + args['save'].strip()
            with open(file_name, 'w+') as f:
                f.write(text)
            print('Saved to file:', file_name)

if __name__ == '__main__':
    main()
