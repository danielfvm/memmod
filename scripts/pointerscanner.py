from dataclasses import dataclass
from memmod import Process, Module

import argparse
import sys


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
        # we want the offset to start from the base so we calculate the offset from the
        # base module and the module the static pointer is in and add it to its offset
        base = proc.find_module(self.module.path)
        if not base:
            print('pointerscanner.py: error: Failed to obtain base module of', self.module.path)
            sys.exit()

        base_offset = self.module.start - base.start
        return base_offset + self.offset


    @property
    def location(self):
        return self.module.start + self.offset

    def find_dynamic_pointers(self, bounds: int) -> list:
        pointers: list[Pointer] = []

        data = proc.read(self.value, bounds+8)

        offset_to_scan_start = self.value - heap.start

        for offset in range(bounds):
            value = int.from_bytes(data[offset:offset+8], sys.byteorder)
            if heap.contains_address(value):
                pointers.append(Pointer(heap, offset_to_scan_start + offset, value))

        del data
        return pointers

    def find_offset_to_address(self, bounds: int, address: int):
        if self.value >= address and address <= self.value + bounds:
            return address - self.value
        return -1


def find_static_pointers(module: Module) -> list[Pointer]:
    data = proc.read(module.start, module.size)

    pointers: list[Pointer] = []

    for offset in range(module.size-8):
        value = int.from_bytes(data[offset:offset+8], sys.byteorder)
        if heap.contains_address(value):
            pointers.append(Pointer(module, offset, value))

    del data
    return pointers


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
        paths.extend(find_pointer_path_to_address(dynamic_pointers, address, bounds, history, _nested-1))

    return paths


def hexvalue(x):
    return int(x, 0)


if __name__ == '__main__':
    arguments = argparse.ArgumentParser()
    arguments.add_argument('-n', '--name', help='Select process by name', type=str)
    arguments.add_argument('-p', '--pid', help='Select process by pid', type=int)
    arguments.add_argument('-a', '--address', help='Use the static pointers to search for a path to this address', type=hexvalue)
    arguments.add_argument('-s', '--save', help='Specify the file to save the results in.', type=str)
    arguments.add_argument('-m', '--module', help='Specify modules to scan for static pointers, default: all', type=str, default=None, nargs='+')
    arguments.add_argument('-r', '--range', help='The range specifies the maximum offset to the address', type=hexvalue, default=0xFF)
    arguments.add_argument('-d', '--depth', help='How long a path can be, default: 3', type=hexvalue, default=3)

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

    print('\nStart searching for static pointers ...')
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

        if args['save'] is not None:
            file_name = 'path.' + args['save'].strip()
            with open(file_name, 'w+') as f:
                f.write(text)
            print('Saved to file:', file_name)
