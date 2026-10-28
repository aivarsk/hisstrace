"""Audit nologin: is it really nologin?

    hisstrace scenario examples/nologin_audit.py -- /usr/sbin/nologin
    hisstrace scenario examples/nologin_audit.py -- /bin/false

A nologin that is really nologin prints its message and exits. It must not
open a terminal (/dev/tty, /dev/pts/*), exec anything, or do shell-like work.
This scenario is `hisstrace run` plus a policy: every syscall is watched
(post.any is all the printer is), whitelisted calls pass silently, every
open/openat path is listed for transparency, and anything else - an
unlisted syscall, a terminal open, an execve - is a problem. At the end it
reports the full syscall list and either every problem or a clean verdict.

FAIL_FAST below selects what happens at the first problem: False collects
them all (full audit), True kills the tracee on the spot and reports what
was seen up to that point.

The whitelist below is collected from real traces of /bin/false and
/usr/sbin/nologin (the Rust build on Ubuntu explains the statx/poll/
sigaltstack entries). Tighten it for your own binaries.
"""

import os
import signal

from hisstrace import any_of, post, pre, tracer

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
        # exit_group never returns, so it has no exit-phase stop: watch its entry
        done = await any_of(post.any(), pre.exit_group())
        if done.name == "exit_group":
            break
        seen.append(done.name)
        problem = None
        if done.name in PATH_ARG:
            path = done.string(PATH_ARG[done.name])
            if path:
                print(f"  open: {path}", flush=True)
                if path.startswith(("/dev/tty", "/dev/pts/")):
                    problem = f"terminal access: open({path!r})"
        elif done.name == "execve":
            problem = f"execve: {done.string('filename')}"
        elif done.name == "connect" and done.succeeded:
            problem = "connect succeeded: the /dev/log attempt must fail"
        elif done.name not in WHITELIST:
            problem = f"off-whitelist syscall: {done.name}{done.args.raw}"
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
