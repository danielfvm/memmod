from memmod import Process, ScanMode
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import enum

import sys

# Open process
proc = Process(name="test")

class HookMode(enum.Enum):
    BEFORE = "before"   # Execute payload before replaced code
    AFTER = "after"     # Execute payload after replaced code (default)
    REPLACE = "none"       # Do not run replaced code

def insert(address: int, payload_code: bytes, hook_size: int = 0, mode = HookMode.AFTER) -> tuple[int, int, int] | None:
    with proc.ptrace() as _:
        jmp_code_len = 5

        module = proc.find_module_with_address(address)
        if not module:
            return None # Invalid address

        binary = proc.read(address, 64)
        if binary[0] == 0xE9:
            return None # Hook already exists, or another jmp that is not allowed to be replaced

        if hook_size < jmp_code_len:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for instruction in md.disasm(binary, 0x0):
                if instruction.address+instruction.size >= jmp_code_len:
                    hook_size = instruction.address+instruction.size
                    break

        payload_len = (0 if mode == HookMode.REPLACE else hook_size) + len(payload_code) + jmp_code_len
        res = proc.scan(ScanMode.MATCH, module.start, module.end, bytes(payload_len))
        if not res:
            return None # No free space found

        payload_address = res[-1].address

        # write binarycode that was replace by the hook + payload_code + jmp offset
        offset = address - (payload_address + payload_len) + jmp_code_len
        if mode == HookMode.AFTER:
            proc.write(payload_address, binary[0:hook_size] + payload_code + b'\xE9' + offset.to_bytes(4, sys.byteorder, signed=True))
        elif mode == HookMode.BEFORE:
            proc.write(payload_address, payload_code + binary[0:hook_size] + b'\xE9' + offset.to_bytes(4, sys.byteorder, signed=True))
        else:
            proc.write(payload_address, payload_code + b'\xE9' + offset.to_bytes(4, sys.byteorder, signed=True))

        # jmp offset
        # nop * (size - hook_len)
        offset = payload_address - (address+jmp_code_len)
        proc.write(address, b"\xE9" + offset.to_bytes(4, sys.byteorder) + b"\x90" * (hook_size - jmp_code_len))

        return (payload_address, payload_len, hook_size) # Successfully inserted hook

base = proc.find_module(proc.name)
assert base != None, "Failed to find base!"

func_a = base.start + base.get_symbol_offset("a")
print("func_a addres:", hex(func_a))

print(insert(func_a + 21, b"\x83\xC0\x01", 8, HookMode.BEFORE))
