#!/bin/python3
from memmod import Process, HookMode

import argparse
import sys


def main():
    global addr_search, access_type

    arguments = argparse.ArgumentParser()
    arguments.add_argument('-n', '--name', help='Select process by name', type=str)
    arguments.add_argument('-p', '--pid', help='Select process by pid', type=int)
    arguments.add_argument('-f', '--factor', help='Set time factor', type=float, required=True)

    args, _ = arguments.parse_known_args()
    args = vars(args)

    # open process by name or it's process id
    if not args['name'] and not args['pid']:
        print('timerhack.py: error: the following arguments are required: -p/--pid or -n/--name')
        sys.exit()

    proc = Process(pid=args['pid'], name=args['name'])
    print('Opend process with pid %d' % proc.pid)

    # 32bit version, not working now
    # hook = insert_hook(clock_gettime_addr + 107, b"\x51\x50\xB9\x02\x00\x00\x00\x8B\x44\x24\x10\x8B\x00\xF7\xE1\x8B\x4C\x24\x10\x89\x01\xB9\x02\x00\x00\x00\x8B\x44\x24\x10\x8B\x40\x04\xF7\xE1\x8B\x4C\x24\x10\x89\x41\x04\x58\x59")

    payload = [
        0x50,                              # 0:  push   rax
        0x51,                              # 1:  push   rcx
        0x53,                              # 2:  push   rbx
        0x48, 0xc7, 0xc1, 0x00, 0, 0, 0,   # 3:  mov    rcx,0x00 (factor)
        0x48, 0xc7, 0xc3, 0x64, 0, 0, 0,   # a:  mov    rbx,0x64 (100)
        0x48, 0x8b, 0x06,                  # 11: mov    rax,QWORD PTR [rsi]
        0x48, 0xf7, 0xe1,                  # 14: mul    rcx
        0x48, 0xf7, 0xf3,                  # 17: div    rbx
        0x48, 0x89, 0x06,                  # 1a: mov    QWORD PTR [rsi],rax
        0x48, 0x8b, 0x46, 0x08,            # 1d: mov    rax,QWORD PTR [rsi+0x8]
        0x48, 0xf7, 0xe1,                  # 21: mul    rcx
        0x48, 0xf7, 0xf3,                  # 24: div    rbx
        0x48, 0x89, 0x46, 0x08,            # 27: mov    QWORD PTR [rsi+0x8],rax
        0x5b,                              # 2b: pop    rbx
        0x59,                              # 2c: pop    rcx
        0x58,                              # 2d: pop    rax 
    ]
    payload[6:10] = int(args['factor'] * 100).to_bytes(4, sys.byteorder)

    clock_gettime_addr = proc.get_libc_function_addr('clock_gettime')
    hook = proc.insert_hook(clock_gettime_addr+33, bytes(payload), mode=HookMode.AFTER)
    if not hook:
        print('timerhack.py: error: Failed to inject hook')
        sys.exit()

    input("Press Enter to continue...")
    proc.remove_hook(hook)

if __name__ == '__main__':
    main()
