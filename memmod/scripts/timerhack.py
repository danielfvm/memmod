#!/bin/python3
from memmod import Process, HookMode, Hook

import argparse
import sys

def set_timer_sdl_gettick(proc: Process, factor: float) -> Hook | None:
    payload = [
        0x51, 								# push  rcx 
        0x53,                               # push  rbx
        0x52,                               # push  rdx
        0x48, 0xC7, 0xC1, 0x00, 0, 0, 0,   	# mov   rcx, 0x00 (factor) 
        0x48, 0xC7, 0xC3, 0x64, 0, 0, 0,  	# mov   rbx, 0x64 (100)
        0x48, 0xF7, 0xE1, 					# mul   rcx
        0x48, 0xF7, 0xF3,                   # div   rbx
        0x5a,                               # pop   rdx
        0x5b,                               # pop   rbx
        0x59 								# pop   rcx
    ]

    payload[6:10] = int(factor * 100).to_bytes(4, sys.byteorder)

    libsdl = proc.find_module("libSDL2-")
    if libsdl == None:
        return None

    offset = libsdl.get_symbol_offset("SDL_GetTicks")
    sdl_getticks_func = int.from_bytes(proc.read(libsdl.start + offset + 0x1672C0, 8), sys.byteorder)

    print("Using SDL_GetTicks from libSDL")
    return proc.insert_hook(sdl_getticks_func+0xD, bytes(payload), mode=HookMode.BEFORE)

def set_timer_clock_gettime(proc: Process, factor: float) -> Hook | None:
    # 32bit version, not working now
    # hook = insert_hook(clock_gettime_addr + 107, b"\x51\x50\xB9\x02\x00\x00\x00\x8B\x44\x24\x10\x8B\x00\xF7\xE1\x8B\x4C\x24\x10\x89\x01\xB9\x02\x00\x00\x00\x8B\x44\x24\x10\x8B\x40\x04\xF7\xE1\x8B\x4C\x24\x10\x89\x41\x04\x58\x59")

    payload = [
        0x50,                               # push  rax
        0x51,                               # push  rcx
        0x53,                               # push  rbx
        0x52,                               # push  rdx
        0x48, 0xc7, 0xc1, 0x00, 0, 0, 0,    # mov   rcx, 0x00 (factor)
        0x48, 0xc7, 0xc3, 0x64, 0, 0, 0,    # mov   rbx, 0x64 (100)
        0x48, 0x8b, 0x06,                   # mov   rax, QWORD PTR [rsi]
        0x48, 0xf7, 0xe1,                   # mul   rcx
        0x48, 0xf7, 0xf3,                   # div   rbx
        0x48, 0x89, 0x06,                   # mov   QWORD PTR [rsi], rax
        0x48, 0x8b, 0x46, 0x08,             # mov   rax, QWORD PTR [rsi+0x8]
        0x48, 0xf7, 0xe1,                   # mul   rcx
        0x48, 0xf7, 0xf3,                   # div   rbx
        0x48, 0x89, 0x46, 0x08,             # mov   QWORD PTR [rsi+0x8],rax
        0x5a,                               # pop   rdx
        0x5b,                               # pop   rbx
        0x59,                               # pop   rcx
        0x58,                               # pop   rax
    ]

    payload[7:11] = int(factor * 100).to_bytes(4, sys.byteorder)

    clock_gettime_addr = proc.get_libc_function_addr('clock_gettime')

    print("Using clock_gettime from libc")
    return proc.insert_hook(clock_gettime_addr+33, bytes(payload), mode=HookMode.AFTER)

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

    # Try SDL speed hack
    hook = set_timer_sdl_gettick(proc, args['factor'])

    # If SDL method didnt work, try the one utilizing "clock_gettime" from libc (still buggy)
    if not hook:
        hook = set_timer_clock_gettime(proc, args['factor'])

    # None of the methods above worked, print error
    if not hook:
        print('timerhack.py: error: Failed to inject hook')
        sys.exit()

    input("Press Enter to continue...")
    proc.remove_hook(hook)

if __name__ == '__main__':
    main()
