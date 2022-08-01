#!/bin/python3

from dataclasses import dataclass
from mmap import PAGESIZE
from memmod import Process, Module

from threading import Thread

import sys

proc = Process(name="supertux")

class Result():
    def __init__(self, address: int) -> None:
        self.address = address

results = []

search = (1015).to_bytes(4, sys.byteorder)

with proc.ptrace() as ptrace:
    for mod in proc.modules:
        if '/dev/' in mod.path or '/memfd/' in mod.path:
            continue
        if '(deleted)' in mod.path:
            continue
        if mod.mode == 'r-xp':
            continue
        if len(mod.path) <= 0:
            continue
        if 'lib/lib' in mod.path:
            continue

        count = 0
        address = mod.start
        while address < mod.end:
            size = min(0x10000, mod.end-address)
            print('%s+%010x %d/100  \r' % (mod.path, mod.offset, round((100/mod.size)*(address-mod.start))), end='')
            data = proc.read(address, size)
            for i in range(size-4):
                if data[i:i+4] == search:
                    count += 1
                    results.append(address+i)
            address += 0x10000-5

        print('%s+%010x 100/100: %d ' % (mod.path, mod.offset, count))

    print(len(results))


