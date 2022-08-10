from memmod import Process

import struct
import sys

proc = Process(name="native_client")
base = proc.find_module(proc.name)
assert base != None, "Failed to locate base module!"
heap = proc.find_module("heap")
assert heap != None, "Failed to locate heap module!"

entity_list_addr = proc.resolve_pointer_chain(base.start + 0x1c4540)
print("Entity list addr:", hex(entity_list_addr))

player = 0
for i in range(5):
    entity_addr = proc.resolve_pointer_chain(entity_list_addr + i * 8)
    name = proc.read(entity_addr + 0x219, 20)
    if name[0] == 0:
        continue
    dead = int.from_bytes(proc.read(entity_addr + 0x7a, 1), sys.byteorder)

    print(name.decode(), hex(entity_addr), dead)
    print(struct.unpack("i", proc.read(entity_addr + 0x6c, 4)))
    print(struct.unpack("d", proc.read(entity_addr + 0x10, 8)))
    print(struct.unpack("H", proc.read(entity_addr + 0x67, 2)))
    print(struct.unpack("H", proc.read(entity_addr + 0x69, 2)))

"""
x = bytes(0x350)
while True:
    _x = proc.read(player, 0x350)
    for i in range(0x350):
        if x[i] is not _x[i]:
            print(i, x[i])
    x = _x
"""
