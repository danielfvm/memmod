from dataclasses import dataclass
from memmod import Process, Module
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn

import cxxfilt
import sys

proc = Process(name=sys.argv[1])
base = proc.find_module(proc.name)
base_proc = proc.find_module(proc.name, mode='r-xp')
base_mem = proc.find_module(proc.name, mode='rw-p')
assert base != None, "Failed to load base module!"
assert base_proc != None, "Failed to load base module!"
assert base_mem != None, "Failed to load base module!"

symbols = base.get_symbols()
symbols_f = list(filter(lambda x: x.entry['st_info']['type'] == 'STT_FUNC' and x.entry['st_value'] != 0, symbols))
symbols_f = list(reversed(sorted(symbols_f, key=lambda x: x.entry['st_value'])))
symbols = list(filter(lambda x: x.entry['st_info']['type'] == 'STT_OBJECT', symbols))

@dataclass
class Reference():
    address: int
    offset: int
    instruction: CsInsn

    def get_function_name(self) -> str:
        for f in symbols_f:
            if f.entry['st_value'] < self.offset:
                return cxxfilt.demangle(f.name)
        return ""


class Object():
    def __init__(self, base: Module, name: str, offset: int) -> None:
        self.base = base
        self.name = name
        self.offset = offset
        self.references = []

    @property
    def address(self):
        return self.base.start + self.offset

    @property
    def demangled_name(self):
        return cxxfilt.demangle(self.name)


binary = proc.read(base_proc.start, base_proc.size)
md = Cs(CS_ARCH_X86, CS_MODE_64)

objects = {}

for instruction in md.disasm(binary, base_proc.offset):
    if instruction.mnemonic != 'mov':
        continue
    if '[' not in instruction.op_str:
        continue
    if 'rip' not in instruction.op_str:
        continue
    if '+' not in instruction.op_str:
        continue

    opcode_offset = int(instruction.op_str[instruction.op_str.find('+')+1:instruction.op_str.find(']')], 16)
    rip = instruction.address+instruction.size
    offset = rip+opcode_offset

    if base_mem.contains_address(base.start+offset):
        address = base.start + offset

        if offset not in objects:
            name = ""
            for x in symbols:
                if x.entry['st_value'] == offset:
                    name = x.name
                    break

            objects[offset] = Object(base, name, offset)
        objects[offset].references.append(Reference(base.start+instruction.address, instruction.address, instruction))

for obj in objects.values():
    print("%s+0x%08x (%016x)  %-4d  %s" % (obj.base.path, obj.offset, obj.address, len(obj.references), obj.demangled_name))
    for ref in obj.references:
        print("\t%s+0x%08x (%016x)  %-40s %s" % (
            obj.base.path, ref.offset, ref.address,
            ref.instruction.mnemonic + ' ' + ref.instruction.op_str,
            ref.get_function_name(),
        ))
    print()

with open("pointers", "w+") as f:
    for obj in objects.values():
        f.write('%s+%x\n' % (obj.base.path, obj.offset))

