import ctypes, ctypes.util
import os

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

try:
    folder = os.path.dirname(os.path.realpath(__file__))
    folder = folder[0:folder.rfind('/')]
    path_libmemscan = folder + '/memscan/libmemscan.so'
    libmemscan = ctypes.CDLL(path_libmemscan)
    libmemscan.memscan.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_int64, ctypes.c_int64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int64, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]
    libmemscan.memscan.restype = ctypes.POINTER(ctypes.c_int64)
except Exception as e:
    print("Failed to find or load libmemscan:", e)
