# Hisstrace

Programmable syscall interception and fault injection in Python.

**strace, with fangs.**

Pure stdlib, no dependencies. Pure Python ptrace bindings, 64-bit x86 and ARM.

## Install

```bash
pip install hisstrace
```

## What works

- ptrace(2) via ctypes: no C extensions, no dependencies;
- syscall number/name tables for x86-64 and AArch64, generated from kernel headers;
- per-architecture register access (x86-64 uses GETREGS, AArch64 uses GETREGSET);
- tracee memory reads and writes, plus `Tracer.exe_image()` / `Tracer.exe_vaddr()`
  for byte-signature scans of the executable, stripped binaries included;
- a `Tracer` that spawns a command or attaches to a pid and iterates syscall
  stops as entry/exit events;
- thread tracing: every thread is followed automatically, including threads
  created later (PTRACE_O_TRACECLONE);
- child processes are opt-in: `await on.fork()` surfaces each new process,
  and `child.follow()` decides to trace it (the default is to let it run free);
- attach to a running process and all its threads by pid (`-p`), following
  threads spawned after the attach;
- software breakpoints inside the tracee: `Tracer.set_breakpoint(addr)` arms
  an int3, the stop surfaces as a `Trap` event with live registers, and the
  original instruction is single-stepped and re-armed for you;
- argument mutation and fault injection at entry: on a pre-match,
  `call.overwrite(count=1)` rewrites named argument registers (names come
  from the syscall table), `call.fail("ENOSPC")` makes the call return -1
  with that errno, and `call.succeed(retval)` skips the call and returns a
  fake success; the kernel never runs failed or succeeded calls, and the
  matching post-match sees the faked result;
- `hisstrace run CMD [ARGS...]`: a strace-style printer, built from the
  scenario API like everything else.

Events carry raw register values: six unsigned arguments at entry, the raw
return register at exit.

## Scenarios

A scenario is one coroutine driven by syscall events:

```python
from hisstrace import post, pre

async def scenario():
    done = await post.read(count=100)  # completion of the next matching read
    print(f"read: {done.data!r} (retval {done.retval})")

    call = await pre.write()  # next write stops before it enters the kernel
    print(f"write: {call.data!r}")
```

Run it against a command:

```bash
hisstrace scenario examples/capture.py -- python3 -c "..."
```

`examples/httpforever.py` prints curl's entire HTTP conversation with
httpforever.com, request bytes marked `->` and response bytes `<-`, by
finding the TCP socket on port 80 and watching `sendto`/`recvfrom` on it.
`examples/byte_by_byte.py` takes the idea one step further: it rewrites the
size argument of every socket read and write to 1 (`call.overwrite` for
count-style calls, one poke inside the msghdr for `recvmsg`/`sendmsg`), so
the kernel moves the whole conversation one byte per syscall, and it tracks
happy-eyeballs connection churn, forked transfers, and fd reuse to do it.
`examples/socket_audit.py` is a linter for the "no timeout set" class of bug
(the one where a library does a blocking call and one slow peer stalls the
event loop): it tracks every socket the app creates
(`socket`/`accept4`/`socketpair`), the `fcntl(F_SETFL, O_NONBLOCK)` and
`ioctl(FIONBIO)` calls that make one non-blocking (what
`socket.setblocking(False)` and `os.set_blocking` emit), treats a connect
that returns EINPROGRESS as proof of non-blocking, and warns at close time
about any socket that lived its whole life blocking, naming the peer it was
connected to.
`examples/nologin_audit.py` is the same shape pointed at trust rather than
performance: run `/usr/sbin/nologin` (or `/bin/false`) and it watches every
syscall against a whitelist, lists every opened path, and calls out terminal
access, execs, or off-whitelist syscalls, with a verdict at the end.
`examples/watch_conn.py` traces a full SSH round of a Go client (socket
traffic across its thread handoff plus every getrandom, ending when the
connection closes); `examples/ssh_decrypted.py` goes the last mile: it plants
a breakpoint on
`crypto/ecdh.x25519ScalarMult` inside the process, recovers the X25519 shared
secret from the trap's registers, derives the session keys, and decrypts the
whole session in pure Python. `examples/ssh_rng_via_syscall.py` does the same
decryption with no symbols and no breakpoints at all: a one-byte patch forces
Go's getrandom off the vDSO and onto the syscall path, the KEX scalar is
picked out of the syscall stream, and the session decrypts from there (this
one example needs `pip install cryptography`; hisstrace itself has no
dependencies).

Or attach to a running process (every thread is traced, and threads spawned
later are picked up automatically):

```bash
hisstrace run -p 4242
hisstrace scenario examples/trackfd.py -p 4242
```

Contract, v1: one scenario runs at a time. While Python code between awaits
runs, the matched tracee stays stopped; reaching the next await resumes it.
Unmatched syscalls pass through unchanged. `post.X` correlates entry and exit
of one invocation and returns a `CompletedCall` (entry args plus `retval`,
`error`, `succeeded`, `failed`, and a capped `data` snapshot for read/write).
`any_of(...)` awaits several matchers and resumes with whichever fires first:

```python
while True:
    event = await any_of(post.read(fd=fd), pre.write(fd=fd), pre.close(fd=fd))
    if event.name == "close":
        break
    print(event.name, event.data)
```

See `examples/trackfd.py` for the full fd-tracking loop. `pre.any()` and
`post.any()` watch every syscall in that phase, which is all `hisstrace run`
is: a strace built from the scenario API, with argument names for every
syscall (generated from kernel prototypes) and C-string reads for pointer
arguments:

```python
while True:
    done = await post.any()
    print(done.name, dict(done.args), done.retval)
    # done.string("path") reads a NUL-terminated string at that argument
```

Child processes are the exception to pass-through: a new process stays frozen
until the scenario decides. `await on.fork()` delivers it; `child.follow()`
traces it, otherwise it runs untraced. Threads need no decision, they are
always followed.

```python
child = await on.fork()
child.follow()          # or don't: the child runs free
print("new process", child.pid, "from thread", child.parent_tid)
```

When the coroutine returns, a spawned tracee keeps running untraced and
`run()` waits it out and returns its exit status; an attached tracee is
detached and `run()` returns 0.
`data` is `None` for syscalls without a buffer; reads that fail give `b""`.
Match filters compare against raw kernel argument values, so remember that
Python adds `O_CLOEXEC` to `os.open` before the kernel sees the flags.

Named arguments come from a table generated out of the kernel's syscall
prototypes (461 syscalls; `make table` regenerates), with `arg0`..`arg5` as
the fallback for anything missing, and are also usable as match filters, as
`count=100` above shows.

## Honest limits

One scenario runs at a time, serially. At entry a scenario can rewrite
arguments (`overwrite`) and the outcome (`fail`, `succeed`), but it cannot
swap one syscall for another, and an in-flight call cannot be cancelled, only
steered. No fd-lifetime tracking: `dup2` aliasing and fd reuse after close
are invisible to plain `fd=` filters (scenarios track fds themselves, as
`examples/byte_by_byte.py` does). Attaching to another user's process fails
with the kernel's `ptrace_scope` error.

## Develop

```bash
make test    # unittest against src/
make lint    # ruff + mypy + line counts
make build   # wheel into dist/
make table   # regenerate syscall tables from kernel headers
```
