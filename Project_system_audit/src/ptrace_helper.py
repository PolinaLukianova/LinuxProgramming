import ctypes
import ctypes.util
import os
import time

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

PTRACE_ATTACH = 16
PTRACE_DETACH = 17

def ptrace_attach(pid):
    res = libc.ptrace(PTRACE_ATTACH, pid, 0, 0)
    if res != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, 'ptrace_attach failed')
    # ждём остановки
    os.waitpid(pid, 0)
    return True

def ptrace_detach(pid):
    res = libc.ptrace(PTRACE_DETACH, pid, 0, 0)
    if res != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, 'ptrace_detach failed')
    return True
