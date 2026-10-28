"""strace, as a scenario: print every syscall with named args and its result.

    hisstrace scenario examples/strace.py -- CMD [ARGS...]
    hisstrace scenario examples/strace.py -p PID

`hisstrace run` does exactly this internally; having it as a scenario file
makes it the starting point for your own printer (different formatting,
filters, a log file, timestamps). Two details worth stealing:

- exit_group never returns, so it has no exit-phase stop: post.any() alone
  would end the run without ever printing it. Watching its entry gives the
  strace-style "= ?" line.
- String arguments are read from the tracee with done.string(name), and
  filters on them compare pointers, not text: read the string, then decide.
"""

import errno

from hisstrace import any_of, arg_names, post, pre

PATHLIKE = {"filename", "path", "oldname", "newname", "oldpath", "newpath"}


def signed(value):
    return value - (1 << 64) if value >= 1 << 63 else value


def fmt(done):
    parts = []
    for name, value in zip(arg_names(done.name), done.args.raw):
        if name in PATHLIKE:
            text = done.string(name)
            if text:
                parts.append(f'{name}="{text}"')
                continue
        v = signed(value)
        parts.append(f"{name}={v if -0xFFFF <= v <= 0xFFFF else hex(v)}")
    suffix = "" if done.tid == done.pid else f"  [tid {done.tid}]"
    return f"{done.name}({', '.join(parts)}) = {fmt_retval(done.retval)}{suffix}"


def fmt_retval(raw):
    value = signed(raw)
    if -4095 <= value <= -1:
        name = errno.errorcode.get(-value)
        return f"-1 {name}" if name else str(value)
    return str(value)


async def scenario():
    while True:
        done = await any_of(post.any(), pre.exit_group())
        if done.name == "exit_group":
            code = signed(done.args.raw[0])
            print(f"exit_group({code}) = ?")
            break
        print(fmt(done))
