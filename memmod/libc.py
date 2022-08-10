import ctypes, ctypes.util
from pathlib import Path

libc = None
libmemscan = None

try:
    path_libc = ctypes.util.find_library("c")
    libc = ctypes.CDLL(path_libc)

    libc.open.argtypes = [ctypes.c_char_p, ctypes.c_int32]
    libc.open.restype = ctypes.c_int32

    libc.read.argtypes = [ctypes.c_int32, ctypes.POINTER(ctypes.c_int8), ctypes.c_size_t]
    libc.read.restype = ctypes.c_ssize_t

    libc.lseek.argtypes = [ctypes.c_int32, ctypes.c_int64, ctypes.c_int32]
    libc.lseek.restype = ctypes.c_ssize_t

    libc.write.argtypes = [ctypes.c_int32, ctypes.c_void_p, ctypes.c_size_t]

    libc.fsync.argtypes = [ctypes.c_int32]
    libc.fsync.restype = ctypes.c_ssize_t

    libc.close.argtypes = [ctypes.c_int32]
    libc.close.restype = ctypes.c_ssize_t

    libc.free.argtypes = [ctypes.c_void_p]
    libc.free.restype = ctypes.c_ssize_t

    libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_uint64
except Exception as e:
    print("Failed to find or load libc:", e)
