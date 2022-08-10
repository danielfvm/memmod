from dataclasses import dataclass
from memmod import Process, Module
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn

import cxxfilt
import sys

proc = Process(name=sys.argv[1])
base = proc.find_module(proc.name)
base_proc = proc.find_module(proc.name, mode='r-xp')
assert base != None, "Failed to load base module!"
assert base_proc != None, "Failed to load base module!"

symbols = base.get_symbols()
symbols_f = list(filter(lambda x: x.entry['st_info']['type'] == 'STT_FUNC' and x.entry['st_value'] != 0, symbols))
symbols_f = list(reversed(sorted(symbols_f, key=lambda x: x.entry['st_value'])))
symbols = list(filter(lambda x: x.entry['st_info']['type'] == 'STT_OBJECT', symbols))


binary = proc.read(base_proc.start, base_proc.size)
md = Cs(CS_ARCH_X86, CS_MODE_64)

func = {}

def get_function_name(address) -> str:
    for f in symbols_f:
        if f.entry['st_value'] < address - base.start:
            return cxxfilt.demangle(f.name)
    return ""


"""
for instruction in md.disasm(binary, base_proc.start):
    if instruction.mnemonic != 'call':
        continue
    if '[' not in instruction.op_str:
        continue
    if 'rip' not in instruction.op_str:
        continue
    if '+' not in instruction.op_str:
        continue

    offset = int(instruction.op_str[instruction.op_str.find('+')+1:instruction.op_str.find(']')], 16)
    rip = instruction.address+instruction.size
    got = rip + offset

    address = int.from_bytes(proc.read(got, 8), sys.byteorder)
    if address not in func:
        mod = proc.find_module_with_address(address)

        if mod == None:
            continue

        func[address] = {
            "module": mod,
            "got": got,
            "address": address,
            "offset": address - mod.start,
            "calls": [ instruction.address ]
        }
    else:
        func[address]["calls"].append(instruction.address)

for f in func.values():
    print(f["module"].path, '+', hex(f["offset"]), hex(f["address"]), len(f["calls"]))
"""


for instruction in md.disasm(binary, base_proc.start):
    if instruction.mnemonic != 'call':
        continue

    op_str = instruction.op_str
    if '[' in op_str:
        continue
    if '+' in op_str:
        continue
    if not op_str[0].isdigit():
        continue

    address = int(op_str, 16)

    if not base_proc.contains_address(address):
        continue

    if address not in func:
        func[address] = {
            "address": address,
            "offset": address - base_proc.start,
            "calls": [ instruction.address ]
        }
    else:
        func[address]["calls"].append(instruction.address)

for f in func.values():
    print("%s+%x (%x)  %d  %s" % (base_proc.path, f["offset"], f["address"], len(f["calls"]), get_function_name(f["address"])))
print(len(func))

# /usr/bin/supertux2+1b4930 (5573d99e4930)  6  Player::set_on_ground(bool)
