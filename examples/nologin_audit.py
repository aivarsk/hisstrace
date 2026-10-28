"""Audit nologin: is it really nologin?

    hisstrace scenario examples/nologin_audit.py -- /usr/sbin/nologin
    hisstrace scenario examples/nologin_audit.py -- /bin/false

A nologin that is really nologin prints its message and exits. It must not
open a terminal (/dev/tty, /dev/pts/*), exec anything, or do shell-like work.
This scenario watches syscall entries (pre.any): every check fires before
the kernel runs the call, so a malicious exec is seen parked at entry, not
after the fact. Whitelisted calls pass silently, every open/openat path is
listed for transparency, and anything else - an unlisted syscall, a terminal
open, an execve, a connect to anything but the syslog socket - is a problem.
At the end it reports the full syscall list and either every problem or a
clean verdict.

FAIL_FAST selects what happens at the first problem: False collects them all
(full audit), True kills the tracee on the spot (the offending call never
runs) and reports what was seen up to that point. Being at entry, you could
just as well deny the call instead of killing the process: call.fail("EPERM")
is one line away.

The whitelist below is collected from real traces of /bin/false and
/usr/sbin/nologin (the Rust build on Ubuntu explains the statx/poll/
sigaltstack entries). Tighten it for your own binaries.
"""

import os
import signal

from hisstrace import pre, tracer
from hisstrace import ptrace

FAIL_FAST = False  # True: kill the tracee at the first problem; False: collect all

# Collected from: strace -f `which false` and strace -f `which nologin`
WHITELIST = {
    "access", "arch_prctl", "read", "write", "open", "close", "brk", "execve",
    "exit_group", "fstat", "getrandom", "mmap", "munmap", "mprotect", "openat",
    "pread64", "prlimit64", "rseq", "set_robust_list", "set_tid_address",
    "newfstatat", "ioctl", "getuid", "futex", "statfs", "getdents64",
    "socket",   # socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0): syslog
    "connect",  # connect(fd, /dev/log): the syslog attempt, expected ENOENT
    # Ubuntu Rust build
    "poll", "rt_sigaction", "rt_sigprocmask", "lseek", "sched_getaffinity",
    "sigaltstack", "statx", "readlink", "fcntl", "gettid",
}

PATH_ARG = {"open": "filename", "openat": "path"}


async def scenario():
    seen = []
    problems = []
    while True:
        # pre.any: every check runs before the kernel does; exit_group's entry
        # (it has no exit-phase stop) ends the audit
        call = await pre.any()
        if call.name == "exit_group":
            break
        seen.append(call.name)
        problem = None
        if call.name in PATH_ARG:
            path = call.string(PATH_ARG[call.name])
            if path:
                print(f"  open: {path}", flush=True)
                if path.startswith(("/dev/tty", "/dev/pts/")):
                    problem = f"terminal access: open({path!r})"
        elif call.name == "execve":
            problem = f"execve: {call.string('filename')}"
        elif call.name == "connect":
            # the only legitimate destination is the syslog socket; anything
            # else (a TCP connect from nologin?) is a problem by itself
            target = call.sockaddr("addr")
            if target.family == 1:
                if target.address != "/dev/log":
                    problem = f"connect to unix socket {target.address!r}"
            else:
                problem = "connect to a non-unix socket"
        elif call.name not in WHITELIST:
            problem = f"off-whitelist syscall: {call.name}{call.args.raw}"
        if problem:
            problems.append(problem)
            if FAIL_FAST:
                os.kill(tracer().pid, signal.SIGKILL)
                break

    print(f"\n{len(seen)} syscalls, {len(set(seen))} distinct: {' '.join(sorted(set(seen)))}")
    if problems:
        print("NOT NOLOGIN:")
        for problem in problems:
            print(f"  {problem}")
    else:
        print("OK: behaves like nologin")
