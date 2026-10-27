"""Thin ctypes wrapper over libc ptrace(2). No external dependencies."""

import ctypes
import errno
import os

libc = ctypes.CDLL(None, use_errno=True)
_ptrace = libc.ptrace
_ptrace.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong)
_ptrace.restype = ctypes.c_long
_waitpid = libc.waitpid
_waitpid.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_int)
_waitpid.restype = ctypes.c_int

TRACEME = 0
PEEKDATA = 2
POKEDATA = 5
CONT = 7
SINGLESTEP = 9
SYSCALL = 24
GETREGS = 12
SETREGS = 13
ATTACH = 16
DETACH = 17
SETOPTIONS = 0x4200
GETEVENTMSG = 0x4201
GETREGSET = 0x4204
SETREGSET = 0x4205

O_TRACESYSGOOD = 0x1
O_TRACEFORK = 0x2
O_TRACEVFORK = 0x4
O_TRACECLONE = 0x8
O_TRACEEXEC = 0x10
O_EXITKILL = 0x100000

EVENT_VFORK = 1
EVENT_FORK = 2
EVENT_CLONE = 3
EVENT_EXEC = 4  # PTRACE_EVENT_* numbers, reported in wait status >> 16

NT_PRSTATUS = 1
SIGTRAP_SYSGOOD = 0x80  # ORed into SIGTRAP by TRACESYSGOOD at syscall stops

WALL = 0x40000000  # __WALL: waitpid reports every traced task, threads included


def ptrace(request, pid, addr=0, data=0):
    """One ptrace(2) call; raises OSError(errno) when the kernel returns -1."""
    ctypes.set_errno(0)
    if _ptrace(request, pid, addr, data) == -1:
        err = ctypes.get_errno()
        if err:
            raise OSError(err, os.strerror(err), f"ptrace({request}, {pid})")
    return


def wait_wall():
    """Wait for the next stop of any traced task; returns (tid, status)."""
    status = ctypes.c_int()
    while True:
        tid = _waitpid(-1, ctypes.byref(status), WALL)
        if tid >= 0:
            return tid, status.value
        err = ctypes.get_errno()
        if err != errno.EINTR:
            raise OSError(err, os.strerror(err), "waitpid(-1)")


def wait_tid(tid):
    """Wait for the next stop of one traced task, threads included."""
    status = ctypes.c_int()
    while True:
        done = _waitpid(tid, ctypes.byref(status), WALL)
        if done >= 0:
            return status.value
        err = ctypes.get_errno()
        if err != errno.EINTR:
            raise OSError(err, os.strerror(err), f"waitpid({tid})")


def wait_tid_nohang(tid):
    """Poll one task with WNOHANG: its status, or None while still running."""
    status = ctypes.c_int()
    done = _waitpid(tid, ctypes.byref(status), WALL | os.WNOHANG)
    if done == tid:
        return status.value
    if done == 0:
        return None
    err = ctypes.get_errno()
    if err == errno.EINTR:
        return None
    raise OSError(err, os.strerror(err), f"waitpid({tid})")


def event_msg(tid):
    """The new task's id, read at a CLONE/FORK/VFORK event stop."""
    value = ctypes.c_ulong()
    ptrace(GETEVENTMSG, tid, 0, ctypes.addressof(value))
    return value.value


def peek(pid, addr, size):
    """Read size bytes of tracee memory at addr.

    A word read that faults (for example past a page boundary) truncates the
    result to the bytes collected so far.
    """
    if size <= 0:
        return b""
    word = ctypes.sizeof(ctypes.c_long)
    mask = (1 << (word * 8)) - 1
    out = bytearray()
    while len(out) < size:
        ctypes.set_errno(0)
        value = _ptrace(PEEKDATA, pid, addr + len(out), 0)
        if value == -1 and ctypes.get_errno():
            break
        out += (value & mask).to_bytes(word, "little")
    return bytes(out[:size])


def peek_cstring(pid, addr, limit=4096):
    """Read a NUL-terminated string from the tracee; best effort, capped."""
    if not addr:
        return ""
    data = peek(pid, addr, limit)
    end = data.find(b"\0")
    if end >= 0:
        data = data[:end]
    return data.decode("utf-8", "replace")


def poke(pid, addr, data):
    """Write data into tracee memory, preserving bytes outside [addr, addr+len)."""
    if not data:
        return
    word = ctypes.sizeof(ctypes.c_long)
    first = addr - addr % word
    last = addr + len(data)
    end = last + (-last % word)
    block = bytearray(peek(pid, first, end - first))
    block[addr - first : addr - first + len(data)] = data
    for off in range(0, len(block), word):
        ctypes.set_errno(0)
        chunk = int.from_bytes(block[off : off + word], "little")
        if _ptrace(POKEDATA, pid, first + off, chunk) == -1:
            err = ctypes.get_errno()
            if err:
                raise OSError(err, os.strerror(err), f"ptrace(POKEDATA, {pid})")
