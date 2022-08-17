from dataclasses import dataclass
from mmap import MAP_ANON, MAP_PRIVATE, PAGESIZE, PROT_EXEC, PROT_READ, PROT_WRITE, mmap
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from .memscan import memscan
from .libc import libc
from .module import Module
from .ptracehelper import PTrace

from Xlib import Xatom, X, XK, protocol, display

import signal
import contextlib
import ctypes
import enum
import sys
import os

class ScanMode(enum.Enum):
    MATCH = 0   # Searches for exect match: x == arg1
    INSIDE = 1  # Searches for number in between: arg1 <= x < arg2

@dataclass
class ScanResult():
    address: int
    data: bytes

    @property
    def value(self):
        return int.from_bytes(self.data, sys.byteorder)

class HookMode(enum.Enum):
    BEFORE = "before"   # Execute payload before replaced code
    AFTER = "after"     # Execute payload after replaced code (default)
    REPLACE = "none"    # Do not run replaced code

@dataclass
class Hook():
    hook_address: int
    hook_size: int
    original_code: bytes

    payload_address: int
    payload_size: int
    payload_code: bytes

@dataclass
class XWindow():
    wid: int|None
    pid: int
    title: str
    clazz: str

class Process():
    def __init__(self, pid=None, name=None) -> None:
        assert pid != None or name != None, "Missing properties in Process: pid or name!"

        self.pid = -1
        if pid is not None:
            self.pid = int(pid)
        else:
            for p in Process.get_all_processes():
                if name in p.name:
                    self.pid = p.pid
                    break

        assert os.path.exists(os.path.join('/proc/', str(self.pid))), "Invalid pid or name, process not found!"

        self._load_status()

        self._libc = None
        self._ptrace = None
        self._mem = None
        self._modules = []
        self._function = {}
        self._detour = {}
        self._breakpoints = {}
        self._x11_display = None
        self._x11_root = None
        self._regs = None

    def __del__(self) -> None:
        if hasattr(self, '_mem') and self._mem:
            libc.close(self._mem)

    @property
    def modules(self) -> list[Module]:
        if not self._modules:
            self.load_modules()
        return self._modules

    @property
    def mem(self):
        if not self._mem:
            self._mem = libc.open(os.path.join('/proc/', str(self.pid), 'mem').encode('utf-8'), 2)
            assert self.mem != -1, "Cannot access /proc/%d/mem, forgot sudo?" % self.pid
        return self._mem

    @property
    def x11_display(self) -> display.Display:
        if not self._x11_display:
            self._x11_display = display.Display()
        return self._x11_display

    @property
    def x11_root(self):
        if not self._x11_root:
            self._x11_root = self.x11_display.screen(0)['root']
        return self._x11_root


    def _x11_query_property(self, win, name, prop_type, format_size, empty=None):
        if isinstance(win, int):
            win = self.x11_display.create_resource_object('window', win)
        if isinstance(name, str):
            name = self.x11_display.get_atom(name)

        result = win.get_full_property(name, prop_type)
        if result and result.format == format_size:
            return result.value
        return empty

    def get_x11_window(self):
        window_ids = ([self.x11_root.id] + list(self._x11_query_property(self.x11_root, '_NET_CLIENT_LIST', Xatom.WINDOW, 32, [])))
        window_list = []

        for wid in window_ids:
            pid = self._x11_query_property(wid, '_NET_WM_PID', Xatom.CARDINAL, 32)
            if pid is not None:
                pid = pid[0]

            title = self._x11_query_property(wid, '_NET_WM_NAME', display.Display.intern_atom(self.x11_display, 'UTF8_STRING'), 8)
            clazz = self._x11_query_property(wid, 'WM_CLASS', Xatom.STRING, 8)

            if pid == self.pid:
                window_list.append(XWindow(wid, pid, title, clazz))

        return window_list

    def send_key(self, window: XWindow, keysym):
        keyCode = self.x11_display.keysym_to_keycode(keysym)

        keyEvent = protocol.event.KeyPress(
            detail = keyCode,
            time = X.CurrentTime,
            root = self.x11_root,
            window = window.wid,
            child = X.NONE,
            root_x = 1,
            root_y = 1,
            event_x = 1,
            event_y = 1,
            state = 0,
            same_screen = 1
        )

        self.x11_display.sync()
        self.x11_display.send_event(window.wid, keyEvent, X.KeyPressMask, True)
        self.x11_display.sync()

    def _load_status(self) -> None:
        self.status = {}

        with open(os.path.join('/proc/', str(self.pid), 'status'), 'r') as file:
            for line in file.readlines():
                args = line.split(':')
                p_name = args[0].strip()
                p_value = args[1].strip()

                # represent value as list
                if p_name in ['Uid', 'Gid', 'Groups']:
                    p_value = p_value.split()

                self.status[p_name] = p_value

        self.name = self.status["Name"]

    def load_modules(self) -> list[Module]:
        self._modules = []

        with open(os.path.join('/proc/', str(self.pid), 'maps'), 'r') as file:
            for line in file.readlines():
                args = line.split()
                address = args[0].split('-')
                device = args[3].split(':')

                self._modules.append(Module(
                    start = int(address[0], 16),
                    end = int(address[1], 16),
                    mode = args[1],
                    offset = int(args[2], 16),
                    major = int(device[0]),
                    minor = int(device[1]),
                    inode = int(args[4]),
                    path = args[5] if len(args) == 6 else "",
                ))

        return self._modules

    def get_path_to_executable(self) -> str|None:
        try:
            return os.readlink(os.path.join('/proc/', str(self.pid), 'exe'))
        except:
            return None

    def write(self, address: int, value: bytes|int|str|bool, size: int|None = None, encoding: str = 'utf-8') -> int:
        libc.lseek(self.mem, address, os.SEEK_SET)
        if type(value) is str:
            value = bytes(value, encoding)
        if type(value) is bytes:
            if size is None:
                size = len(value)
            return libc.write(self.mem, value + bytes(max(size-len(value), 0)), size)
        if type(value) is int or type(value) is bool:
            if size is None:
                size = 8 if value.bit_length() / 8 > 4 else 4
            return libc.write(self.mem, value.to_bytes(size, sys.byteorder), size)
        return 0

    def read(self, address: int, size: int) -> bytes:
        buffer = (ctypes.c_int8*size)()
        libc.lseek(self.mem, address, os.SEEK_SET)
        libc.read(self.mem, buffer, size)

        return bytes(buffer)

    def scan(self, mode: ScanMode, start: int, end: int, arg1: bytes|int, arg2: bytes|int|None = None, chunksize: int = 2048) -> list[ScanResult]:
        size1 = 0
        size2 = 0

        if type(arg1) is int:
            size1 = 8 if arg1.bit_length() / 8 > 4 else 4
            arg1 = arg1.to_bytes(size1, sys.byteorder)
        elif type(arg1) is bytes:
            size1 = len(arg1)

        if type(arg2) is int:
            size2 = 8 if arg2.bit_length() / 8 > 4 else 4
            arg2 = arg2.to_bytes(size2, sys.byteorder)
        elif type(arg2) is bytes:
            size2 = len(arg2)
        else:
            arg2 = b''

        if mode == ScanMode.INSIDE:
            assert arg2 != None, "arg2 must be set in ScanMode.INSIDE!"
            assert size1 == size2, "arg1 and arg2 must have the same size!"

        results = memscan(self.mem, mode.value, start, end, arg1, arg2, size1, chunksize)

        return [ ScanResult(*x) for x in results ]


    def find_module(self, path: str|None, mode: str|None = None, offset: int|None = None) -> Module | None:
        for m in self.modules:
            if path != None and path not in m.path:
                continue
            if offset != None and offset != m.offset:
                continue
            if mode != None and len(mode) == 4 and mode != m.mode:
                continue
            return m
        return None

    def find_module_with_address(self, address) -> Module|None:
        for m in self.modules:
            if m.contains_address(address):
                return m
        return None

    @contextlib.contextmanager
    def ptrace(self):
        was_stopped = False
        try:
            if not self._ptrace:
                self._ptrace = PTrace()
                self._ptrace.attach(self.pid)
            else:
                was_stopped = self._ptrace.stopped
                self._ptrace.stop()
            yield self._ptrace
        except ChildProcessError:
            raise RuntimeError('ptrace failed to connect, forgot sudo or is another debugger already connected?')
        finally:
            if self._ptrace and not was_stopped:
                self._ptrace.cont()

    def search_pattern(self, module: Module, signature: bytes, mask: bytes) -> int:
        assert len(signature) == len(mask), 'Signature and mask must have same length!'

        size = len(signature)

        for addr in range(module.start, module.end, size):
            data = self.read(addr, size * 2)
            for j in range(size):
                for i in range(size):
                    if mask[i] != '?' and signature[i] != data[i+j]:
                        break
                    elif i == size - 1:
                        return addr + i + j
        return 0

    def resolve_pointer_chain(self, baseaddr, offsets: list[int] = [0]) -> int:
        addr = baseaddr

        for offset in offsets:
            if self.find_module_with_address(addr) is None:
                return 0 # Invalid pointer

            addr = int.from_bytes(self.read(addr, 8), sys.byteorder) + offset

        return addr

    def get_libc(self) -> Module:
        self._libc = self._libc or self.find_module('libc.so') or self.find_module('libc-')
        assert self._libc != None, "Failed to locate libc"

        return self._libc

    def get_libc_function_addr(self, name: str) -> int:
        # for faster loading time check if function has been used already
        if name in self._function:
            return self._function[name]

        libc = self.get_libc()

        sym_addr = libc.get_symbol_offset(name)

        self._function[name] = libc.start + sym_addr
        return libc.start + sym_addr

    def get_libc_function(self, name: str):
        func_addr = self.get_libc_function_addr(name)

        def run(*args) -> int:
            return self.run_function(func_addr, *args)
        return run

    # Allocates memory if a string was passed
    def _pre_function_arg(self, arg):
        if type(arg) == int or type(arg) == bool:
            return int(arg)

        if type(arg) == str:
            addr = self.get_libc_function("malloc")(len(arg)+1)
            self.write(addr, arg+'\0')
            return addr

        return 0

    # clearup memory allocated in _pre_function_arg if a string was passed as argument
    def _post_function_arg(self, arg, _arg):
        if type(_arg) == str:
            self.get_libc_function("free")(arg)

    # https://ancat.github.io/python/2019/01/01/python-ptrace.html
    def run_function(self, addr: int, *_args):
        args = list(map(lambda arg: self._pre_function_arg(arg), _args))

        with self.ptrace() as ptrace:
            # Read register and make a copy
            regs = ptrace.get_registers()
            backup_regs = ptrace.get_registers()

            # Overwrite registers with our the new parameters and address to function
            regs.rax = addr
            regs.rdi = 0 if len(args) <= 0 else args[0]
            regs.rsi = 0 if len(args) <= 1 else args[1]
            regs.rdx = 0 if len(args) <= 2 else args[2]
            regs.rcx = 0 if len(args) <= 3 else args[3]
            regs.r8 = 0 if len(args) <= 4 else args[4]
            regs.r9 = 0 if len(args) <= 5 else args[5]
            ptrace.set_registers(regs)

            # 48 81 e4 00 f0 ff ff    and    rsp,0xfffffffffffff000
            # ff d0                   call   rax
            # cc                      int3 
            backup = self.read(regs.rip, 4)
            self.write(regs.rip, 0xccd0ff)

            # Execute our injected code until breakpoint (int3)
            ptrace.cont()
            ptrace.waitsig(signal.SIGTRAP)

            # Read registers for return value
            regs = ptrace.get_registers()

            # load backup
            ptrace.set_registers(backup_regs)
            self.write(backup_regs.rip, backup)

        # clearup memory allocated in _pre_function_arg if a string was passed as argument
        for arg, _arg in zip(args, _args):
            self._post_function_arg(arg, _arg)

        # return result of function, stored in rax
        return regs.rax

    def load_shaderd_library(self, path: str, flags: int = 0x1) -> int: # RTLD_LAZY = 0x1
        path = os.path.realpath(path)
        assert os.path.exists(path), "File does not exist"

        dlopen = self.get_libc_function('dlopen') or self.get_libc_function('__libc_dlopen_mode')
        assert dlopen != None, "Failed to locate dlopen in libc"

        # call libc function with path and flags
        return dlopen(path, flags)


    def create_detour(self, address: int, dest: int, size: int = 0, trampoline: bool = False) -> int:
        hook_len = 14
        jmp_code = bytes([ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 ]) # 8 byte address follows

        binary = self.read(address, 32)

        # if size wasn't set or is too small, we try to automatically estimate the size
        if size < hook_len:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for instruction in md.disasm(binary, 0x0):
                if instruction.address >= hook_len:
                    size = instruction.address
                    break

        # set detour jmp
        hook_code = jmp_code + dest.to_bytes(8, sys.byteorder) + b'\x90' * (size-hook_len)
        self.write(address, hook_code)

        # set trampoline
        region = 0
        if trampoline:
            mmap = self.get_libc_function('mmap')
            region = mmap(0, PAGESIZE, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, 0, 0)
            if region == -1:
                return 0

            code = binary[0:size] + jmp_code + (address+size).to_bytes(8, sys.byteorder)
            self.write(region, code)

        self._detour[address] = { 'original': binary[0:size], 'trampoline': region }

        return region

    def destroy_detour(self, address: int) -> bool:
        if address not in self._detour:
            return False

        original, trampoline = self._detour[address].values()

        # restore original binary code 
        self.write(address, original)

        # delete memory region
        if trampoline:
            munmap = self.get_libc_function('munmap')
            munmap(trampoline, PAGESIZE)

        return True


    def insert_hook(self, address: int, payload_code: bytes, hook_size: int = 0, mode = HookMode.AFTER) -> Hook | None:
        jmp_code_len = 5

        module = self.find_module_with_address(address)
        if not module:
            return None # Invalid address

        binary = self.read(address, 64)
        if binary[0] == 0xE9:
            return None # Hook already exists, or another jmp that is not allowed to be replaced

        if hook_size < jmp_code_len:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for instruction in md.disasm(binary, 0x0):
                if instruction.address+instruction.size >= jmp_code_len:
                    hook_size = instruction.address+instruction.size
                    break

        payload_len = (0 if mode == HookMode.REPLACE else hook_size) + len(payload_code) + jmp_code_len
        res = self.scan(ScanMode.MATCH, module.start, module.end, bytes(payload_len))
        if not res:
            return None # No free space found

        payload_address = res[-1].address

        # write binarycode that was replace by the hook + payload_code + jmp offset
        offset = address - (payload_address + payload_len) + jmp_code_len
        if mode == HookMode.AFTER:
            self.write(payload_address, binary[0:hook_size] + payload_code + b'\xE9' + offset.to_bytes(4, sys.byteorder, signed=True))
        elif mode == HookMode.BEFORE:
            self.write(payload_address, payload_code + binary[0:hook_size] + b'\xE9' + offset.to_bytes(4, sys.byteorder, signed=True))
        else:
            self.write(payload_address, payload_code + b'\xE9' + offset.to_bytes(4, sys.byteorder, signed=True))

        # jmp offset
        # nop * (size - hook_len)
        offset = payload_address - (address+jmp_code_len)
        self.write(address, b"\xE9" + offset.to_bytes(4, sys.byteorder) + b"\x90" * (hook_size - jmp_code_len))

        return Hook(address, hook_size, binary[0:hook_size], payload_address, payload_len, payload_code)

    def remove_hook(self, hook: Hook) -> bool:
        if self.read(hook.hook_address, 1)[0] != 0xE9:
            return False # Hook already removed

        removed_hook = self.write(hook.hook_address, hook.original_code, hook.hook_size) == hook.hook_size
        removed_payload = self.write(hook.payload_address, b'\x00' * hook.payload_size) == hook.payload_size

        return removed_hook and removed_payload


    @staticmethod
    def get_all_processes() -> list:
        path = '/proc/'

        # A process is a folder with a number representing its process id
        def is_process_folder(subfolder):
            path_to_folder = os.path.join(path, subfolder)
            return os.path.isdir(path_to_folder) and subfolder.isdigit()

        pids = [d for d in os.listdir(path) if is_process_folder(d)]

        def load_processes(pid):
            try:
                return Process(pid=pid)
            except PermissionError:
                return None

        return list(filter(lambda x: x is not None, list(map(load_processes, pids))))

    def add_breakpoint(self, address: int, handle, data = None):
        original = self.read(address, 1)

        self._breakpoints[address] = {
            'original': original,
            'handle': handle,
            'data': data,
        }

    def listen(self):
        with self.ptrace() as ptrace:
            for address in self._breakpoints.keys():
                self.write(address, 0xCC, 1)

            try:
                while self._breakpoints:
                    ptrace.cont()
                    ptrace.waitsig(signal.SIGTRAP)
                    regs = ptrace.get_registers()

                    regs.rip -= 1

                    address = regs.rip

                    if address not in self._breakpoints:
                        continue

                    info = self._breakpoints[address]

                    # replace breakpoint with original binary code
                    self.write(address, info['original'])

                    con = info['handle'](regs, info['data'])
                    ptrace.set_registers(regs)

                    # if the handle returned true, we will keep the breakpoint
                    if con == True:
                        # step forward so that we execute the original code
                        ptrace.singlestep()
                        ptrace.waitsig(signal.SIGTRAP)
                        ptrace.singlestep()
                        ptrace.waitsig(signal.SIGTRAP)
                        ptrace.singlestep()
                        ptrace.waitsig(signal.SIGTRAP)
                        self.write(address, 0xCC, 1)
                    else:
                        del self._breakpoints[address]

            except KeyboardInterrupt:
                ptrace.stop()
                for address, info in self._breakpoints.items():
                    self.write(address, info['original'])
