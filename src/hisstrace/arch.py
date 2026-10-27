"""Syscall register layouts for x86-64 and AArch64.

One Arch class, configured per architecture: register block struct, syscall
number register, return register, argument registers, and whether register
access goes through GETREGS (x86-64) or GETREGSET (AArch64).
"""

import ctypes
import platform

from . import ptrace
from .table import TABLES


class Amd64Regs(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "r15",
            "r14",
            "r13",
            "r12",
            "rbp",
            "rbx",
            "r11",
            "r10",
            "r9",
            "r8",
            "rax",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "orig_rax",
            "rip",
            "cs",
            "eflags",
            "rsp",
            "ss",
            "fs_base",
            "gs_base",
            "ds",
            "es",
            "fs",
            "gs",
        )
    ]


class Aarch64Regs(ctypes.Structure):
    _fields_ = [(f"x{i}", ctypes.c_ulonglong) for i in range(31)]
    _fields_ += [("sp", ctypes.c_ulonglong), ("pc", ctypes.c_ulonglong), ("pstate", ctypes.c_ulonglong)]


class Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class Arch:
    """Register access plus the syscall tables for one architecture."""

    def __init__(self, machine, reg_struct, nr_reg, ret_reg, arg_regs, regset, pc_reg):
        self.machine = machine
        self._struct = reg_struct
        self._nr, self._ret = nr_reg, ret_reg
        self._args = arg_regs
        self._pc = pc_reg
        self._regset = regset  # True: GETREGSET/SETREGSET, False: GETREGS/SETREGS
        self.syscalls = TABLES.get(machine, {})
        self.names = {name: number for number, name in self.syscalls.items()}

    def get(self, pid):
        regs = self._struct()
        if self._regset:
            iov = Iovec(ctypes.addressof(regs), ctypes.sizeof(regs))
            ptrace.ptrace(ptrace.GETREGSET, pid, ptrace.NT_PRSTATUS, ctypes.addressof(iov))
        else:
            ptrace.ptrace(ptrace.GETREGS, pid, 0, ctypes.addressof(regs))
        return regs

    def set(self, pid, regs):
        if self._regset:
            iov = Iovec(ctypes.addressof(regs), ctypes.sizeof(regs))
            ptrace.ptrace(ptrace.SETREGSET, pid, ptrace.NT_PRSTATUS, ctypes.addressof(iov))
        else:
            ptrace.ptrace(ptrace.SETREGS, pid, 0, ctypes.addressof(regs))

    def number(self, regs):
        return getattr(regs, self._nr)

    def set_number(self, regs, value):
        setattr(regs, self._nr, value)

    def args(self, regs):
        return tuple(getattr(regs, name) for name in self._args)

    def set_arg(self, regs, index, value):
        setattr(regs, self._args[index], value)

    def retval(self, regs):
        return getattr(regs, self._ret)

    def set_retval(self, regs, value):
        setattr(regs, self._ret, value)

    def pc(self, regs):
        return getattr(regs, self._pc)

    def set_pc(self, regs, value):
        setattr(regs, self._pc, value)

    def syscall_name(self, number):
        return self.syscalls.get(number, f"sys_{number}")


AMD64 = Arch("x86_64", Amd64Regs, "orig_rax", "rax", ("rdi", "rsi", "rdx", "r10", "r8", "r9"), False, "rip")
AARCH64 = Arch("aarch64", Aarch64Regs, "x8", "x0", tuple(f"x{i}" for i in range(6)), True, "pc")

_current = None


def current():
    global _current
    if _current is None:
        _current = {"x86_64": AMD64, "aarch64": AARCH64}.get(platform.machine())
        if _current is None:
            raise RuntimeError(f"unsupported architecture: {platform.machine()}")
    return _current
