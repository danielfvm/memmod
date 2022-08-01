#!/bin/python3

from dataclasses import dataclass
from memmod import Process, Module

import argparse
import sys

from memmod.process import ScanMode, ScanResult


# global variables
proc: Process
heap: Module


@dataclass
class Pointer():
    module: Module
    offset: int     # offset starting from module.start
    value: int      # address where it is located

    @property
    def base_offset(self):
        return self.module.offset + self.offset

    @property
    def location(self):
        return self.module.start + self.offset

    def find_dynamic_pointers(self, bounds: int) -> list:
        pointers: list[Pointer] = []

        data = proc.read(self.value, bounds+8)

        offset_to_scan_start = self.value - heap.start

        offset = 0
        while offset < bounds:
            value = int.from_bytes(data[offset:offset+8], sys.byteorder)
            if heap.contains_address(value):
                pointers.append(Pointer(heap, offset_to_scan_start + offset, value))
                offset += 7
            offset += 1

        return pointers

    def find_offset_to_address(self, bounds: int, address: int):
        if self.value <= address and address <= self.value + bounds:
            return address - self.value
        return -1


def find_static_pointers(module: Module) -> list[Pointer]:
    results = proc.scan(ScanMode.INSIDE, module.start, module.end, heap.start, heap.end)

    def result_to_pointer(res: ScanResult) -> Pointer:
        offset = res.address - module.start
        return Pointer(module, offset, res.value)

    return list(map(result_to_pointer, results))


def find_pointer_path_to_address(start_pointers: list[Pointer], address: int, bounds: int, _history=[], _nested=3):
    if _nested <= 0:
        return []

    paths = []

    for pointer in start_pointers:
        history = _history + [pointer]

        offset = pointer.find_offset_to_address(bounds, address)
        if offset >= 0:
            paths.append(history+[offset])
            continue

        dynamic_pointers = pointer.find_dynamic_pointers(bounds)
        results = find_pointer_path_to_address(dynamic_pointers, address, bounds, history, _nested-1)
        paths.extend(results)

    return paths


def hexvalue(x):
    return int(x, 0)


def main():
    global proc, heap

    arguments = argparse.ArgumentParser()
    arguments.add_argument('-n', '--name', help='Select process by name', type=str)
    arguments.add_argument('-p', '--pid', help='Select process by pid', type=int)
    arguments.add_argument('-a', '--address', help='Use the static pointers to search for a path to this address', type=hexvalue)
    arguments.add_argument('-s', '--save', help='Specify the file to save the results in.', type=str)
    arguments.add_argument('-m', '--module', help='Specify modules to scan for static pointers, default: all', type=str, default=None, nargs='+')
    arguments.add_argument('-r', '--range', help='The range specifies the maximum offset to the address', type=hexvalue, default=0xFF)
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
    _heap = proc.find_module('[heap]')
    if not _heap:
        print('pointerscanner.py: error: Failed to open heap module.')
        sys.exit()
    else:
        heap = _heap


    # search static pointers
    static_pointers: list[Pointer] = []

    if args['staticfile']:
        with open(args['staticfile'], 'r') as file:
            for line in file.readlines():
                data = line.split('+')
                module = proc.find_module(data[0])

                if module == None:
                    print("Failed to find module", data[0])
                    continue

                offset = int(data[1], 16)
                value = int.from_bytes(proc.read(module.start+offset, 8), sys.byteorder)
                if heap.contains_address(value):
                    print(hex(value))
                    static_pointers.append(Pointer(module, offset, value))
        print('Loaded static_pointers:', len(static_pointers))
    else:
        print('\nStart searching for static pointers ...')
        if not args['module']:
            for mod in proc.modules:
                if '/dev/' in mod.path or '/memfd/' in mod.path:
                    continue
                if '(deleted)' in mod.path or ('[' in mod.path and ']' in mod.path):
                    continue
                if mod.mode != 'r--p':
                    continue
                if len(mod.path) <= 0:
                    continue

                results = find_static_pointers(mod)
                static_pointers.extend(results)
                print('%s: %d' % (mod.path, len(results)))
        else:
            for name in args['module']:
                mod = proc.find_module(name, mode='rw-p')
                if not mod:
                    print('pointerscanner.py: error: Failed to locate module:', name)
                else:
                    results = find_static_pointers(mod)
                    static_pointers.extend(results)
                    print('%s: %d' % (mod.path, len(results)))

        print('Total static_pointers found:', len(static_pointers))
        if args['save'] is not None:
            file_name = 'static.' + args['save'].strip()
            with open(file_name, 'w+') as f:
                for ptr in static_pointers:
                    f.write('%s + 0x%x\n' % (ptr.module.path, ptr.base_offset))
            print('Saved to file:', file_name)


    # search paths to address
    if args['address'] is not None:
        print('\nStart searching for pointer paths ...')

        text = ''
        for ptr in static_pointers:
            results = find_pointer_path_to_address([ptr], int(args['address']), int(args['range']), _nested=int(args['depth']))

            # print the path
            for result in results:
                line = '%s + %-12x ' % (result[0].module.path, result[0].base_offset)
                for i in range(1, len(result)-1):
                    line += '%-8x ' % (result[i].location - result[i-1].value)
                line += '%-5x' % result[-1]
                text += line + '\n'
                print(line)

        print('Total paths found:', len(text.split('\n'))-1)
        if args['save'] is not None:
            file_name = 'path.' + args['save'].strip()
            with open(file_name, 'w+') as f:
                f.write(text)
            print('Saved to file:', file_name)


if __name__ == '__main__':
    main()
