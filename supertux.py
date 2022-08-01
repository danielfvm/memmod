from mmap import PAGESIZE
from memmod import Process, ScanMode

import time
import sys

# Open process
proc = Process(name="supertux2")
heap = proc.find_module("heap")
assert heap != None, "Heap not found!"

results = proc.scan(ScanMode.INSIDE, heap.start, heap.end, heap.start, heap.end)
print(len(results))
for i, r in enumerate(results):
    print(i, r.address, hex(r.value))

sys.exit()

# Hello World 
puts = proc.get_libc_function("puts")

# Find base module
modulebase = proc.find_module(proc.name)
assert modulebase != None, "Failed to find module base"

heap = proc.find_module("[heap]")
assert heap != None, "Failed to find heap"


health_addr = proc.resolve_pointer_chain(modulebase.start+0x1c4538, [0x100])
print(int.from_bytes(proc.read(health_addr, 4), sys.byteorder))

while 1:
    proc.write(health_addr, 100)


# Breakpoint example
# addr: 0x00005606ae0fa566  access: write  offset: /usr/bin/supertux2+0x311566  
# asm:  mov dword ptr [rdx + 4], eax
"""
def handle(regs, _):
    print("bonus value:", regs.rax)
    puts("bonus value " + str(regs.rax))

    regs.rax = 2 # our cheat

    return True

print("breakpoint:", hex(modulebase.start + 0x311566))
proc.add_breakpoint(modulebase.start + 0x311566, handle)
proc.listen()

sys.exit()
"""


# Pointer chain
static_ptr = modulebase.start + 0x6CBC40
coin_ptr_addr = proc.resolve_pointer_chain(static_ptr, [0x28, 0x20, 0x0])
proc.write(coin_ptr_addr, 1000)
print("Coin addr:", hex(coin_ptr_addr))



# /usr/bin/supertux2 + 6cad80       10       38       1e4
"""
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

pointers = {}

with proc.ptrace() as ptrace:
    for address in range(heap.start, heap.end, PAGESIZE-9):
        data = proc.read(address, PAGESIZE)
        for i in range(PAGESIZE-8):
            ptr = int.from_bytes(data[i:i+8], sys.byteorder)
            if heap.contains_address(ptr):
                pointers[address+i] = {
                    "location": address+i,
                    "value": ptr,
                }

    with open("pointers3", "w+") as file:
        for ptr in pointers.values():
            file.write('%x %x\n' % (ptr["location"], ptr["value"]))

with open("pointers3", "r") as file:
    for line in file.readlines():
        data = line.split()
        location = int(data[0], 16)
        value = int(data[1], 16)
        pointers[location] = {
            "location": location,
            "value": value,
        }


# a std::vector is a struct with 3 pointers next to each other
for ptr in pointers.values():
    if ptr["value"] not in pointers:
        continue

    # check if below pointer is another pointer
    next_ptr = ptr["location"]+0x8
    if next_ptr not in pointers:
        continue

    if pointers[next_ptr]["value"]-0x8 not in pointers:
        continue

    if ptr["location"]+0x10 not in pointers:
        continue

    size = pointers[next_ptr]["value"]-ptr["value"]
    if size % 8 != 0 or size <= 0:
        continue

    size = int(size / 8)

    valid = True
    for item in range(ptr["value"], pointers[next_ptr]["value"], 0x8):
        if item not in pointers:
            valid = False
            break

    if not valid:
        continue

    print(hex(ptr["location"]), size)
