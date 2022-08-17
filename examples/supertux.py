from dataclasses import dataclass
from mmap import PAGESIZE
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from memmod import Process, ScanMode, module

import enum
import time
import sys

# Open process
proc = Process(name="kono")
print(proc.pid)

# Find base module
modulebase = proc.find_module(proc.name)
assert modulebase != None, "Failed to find module base"

heap = proc.find_module("heap")
assert heap != None, "Heap not found!"


# Hello World 
puts = proc.get_libc_function("puts")


# Pointer chain
static_ptr = modulebase.start + 0x6CBC40
coin_ptr_addr = proc.resolve_pointer_chain(static_ptr, [0x28, 0x20, 0x0])
proc.write(coin_ptr_addr, 1000)
print("Coin addr:", hex(coin_ptr_addr))

# onground
static_ptr = modulebase.start + 0x6cbd80
onground_ptr_addr = proc.resolve_pointer_chain(static_ptr, [0x10,    0x8,     0x8,     0xa0,    0xa0])
print("OnGround addr:", hex(onground_ptr_addr))


# Breakpoint example
# addr: 0x00005606ae0fa566  access: write  offset: /usr/bin/supertux2+0x311566  
# asm:  mov dword ptr [rdx + 4], eax
def handle_damage(regs, _):
    print("bonus value:", regs.rax)
    puts("bonus value " + str(regs.rax))

    regs.rax = 2 # our cheat

    return True

# Start listen
print("damage breakpoint:", hex(modulebase.start + 0x311566))
proc.add_breakpoint(modulebase.start + 0x311566, handle_damage)
proc.listen()




"""
# /usr/bin/supertux2 + 6cad80       10       38       1e4
entity_static_ptr = modulebase.start + 0x6cbd80

start = proc.resolve_pointer_chain(entity_static_ptr, [0x10, 0x0])
end = proc.resolve_pointer_chain(entity_static_ptr, [0x18, 0x0])
end_invalid = proc.resolve_pointer_chain(entity_static_ptr, [0x20, 0x0, 0x0])
end_invalid_ = proc.resolve_pointer_chain(entity_static_ptr, [0x28, 0x0])
print(hex(start), hex(end), hex(end_invalid), hex(end_invalid_))

# 0x55e02e6b93e0 0x55e02e6b9d20 0x55e02ea29bb0 0x0

for i in range(start, end, 0x8):
    entity_ptr = int.from_bytes(proc.read(i, 8), sys.byteorder)
    #onground = int.from_bytes(proc.read(entity_ptr + 0x1e4, 1), sys.byteorder)
    print("%d (%x) -> %x" % ((i-start) / 8, i, entity_ptr))

sys.exit()
"""
