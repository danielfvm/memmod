from .libc import libc

import ctypes, ctypes.util
import signal
import os

PTRACE_PEEKTEXT   = 1
PTRACE_PEEKDATA   = 2
PTRACE_POKETEXT   = 4
PTRACE_POKEDATA   = 5
PTRACE_CONT       = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS    = 12
PTRACE_SETREGS    = 13
PTRACE_ATTACH     = 16
PTRACE_DETACH     = 17
PTRACE_GETSIGINFO = 0x4202

class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

    def __repr__(self):
        return str(list(map(lambda x: (x[0], getattr(self, x[0])), self._fields_)))


class siginfo_t(ctypes.Structure):
    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("_pad", ctypes.c_int * 29),
        ("si_pid", ctypes.c_uint)
    ]

class PTrace():
    def __init__(self) -> None:
        self.pid = 0
        self.stopped = False

    def attach(self, pid) -> bool:
        self.pid = pid

        libc.ptrace(PTRACE_ATTACH, self.pid, None, None)

        return self.waitsig(signal.SIGSTOP)

    def stop(self) -> bool:
        if self.stopped:
            return True
        os.kill(self.pid, signal.SIGSTOP)
        return self.waitsig(signal.SIGSTOP)

    def get_registers(self) -> user_regs_struct:
        assert self.pid != 0, "Process not attached!"
        registers = user_regs_struct()
        libc.ptrace(PTRACE_GETREGS, self.pid, None, ctypes.byref(registers))

        return registers

    def set_registers(self, registers) -> None:
        assert self.pid != 0, "Process not attached!"
        libc.ptrace(PTRACE_SETREGS, self.pid, None, ctypes.byref(registers))

    def singlestep(self) -> None:
        assert self.pid != 0, "Process not attached!"
        libc.ptrace(PTRACE_SINGLESTEP, self.pid, None, None)
        self.stopped = False

    def cont(self) -> None:
        assert self.pid != 0, "Process not attached!"
        libc.ptrace(PTRACE_CONT, self.pid, None, None)
        self.stopped = False

    def waitsig(self, signal) -> bool:
        assert self.pid != 0, "Process not attached!"
        stat = os.waitpid(self.pid, 0)
        self.stopped = True
        return os.WIFSTOPPED(stat[1]) and os.WSTOPSIG(stat[1]) == signal

    def detach(self) -> bool:
        assert self.pid != 0, "Process not attached!"
        result = libc.ptrace(PTRACE_DETACH, self.pid, None, None)
        self.pid = 0
        self.stopped = False
        return result != -1

    def write(self, address, data):
        assert self.pid != 0, "Process not attached!"
        libc.ptrace(PTRACE_POKEDATA, self.pid, ctypes.c_void_p(address), data)

    def read(self, address):
        assert self.pid != 0, "Process not attached!"
        return libc.ptrace(PTRACE_PEEKDATA, self.pid, ctypes.c_void_p(address), None)

