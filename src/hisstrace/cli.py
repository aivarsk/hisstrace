"""hisstrace command line: raw tracing and scenario files."""

import argparse
import errno
import sys

from . import __version__
from .scenario import arg_names, post
from .scenario import load as load_scenario
from .scenario import run as run_scenario
from .trace import signed

# argument names whose values read better as the tracee's string
PATHLIKE = {"path", "pathname", "filename", "oldname", "newname", "oldpath", "newpath"}


def fmt_arg(value):
    value = signed(value)
    return str(value) if -0xFFFF <= value <= 0xFFFF else hex(value)


def fmt_retval(raw):
    value = signed(raw)
    if -4095 <= value <= -1:
        name = errno.errorcode.get(-value)
        return f"-1 {name}" if name else str(value)
    return str(value)


def fmt_call(done):
    parts = []
    for name, value in zip(arg_names(done.name), done.args.raw):
        if name in PATHLIKE:
            text = done.string(name)
            if text:
                parts.append(f'{name}="{text}"')
                continue
        parts.append(f"{name}={fmt_arg(value)}")
    suffix = "" if done.tid == done.pid else f"  [tid {done.tid}]"
    return f"{done.name}({', '.join(parts)}) = {fmt_retval(done.retval)}{suffix}"


def run(argv=None, pid=None):
    """strace, built from the scenario API: watch every syscall completion."""

    async def trace_all():
        while True:
            print(fmt_call(await post.any()))

    return run_scenario(trace_all, argv=argv, pid=pid)


def strip_ddash(argv):
    return argv[1:] if argv[:1] == ["--"] else argv


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hisstrace", description="strace, with fangs.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="trace a command and print its syscalls")
    run_p.add_argument("--pid", "-p", type=int, help="attach to a running process and its threads (before CMD)")
    run_p.add_argument("argv", metavar="CMD", nargs=argparse.REMAINDER)
    sc_p = sub.add_parser("scenario", help="drive a scenario coroutine against a command")
    sc_p.add_argument("--pid", "-p", type=int, help="attach to a running process and its threads (before SCENARIO.py)")
    sc_p.add_argument("file", metavar="SCENARIO.py")
    sc_p.add_argument("argv", metavar="CMD", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            if args.pid:
                if strip_ddash(args.argv):
                    parser.error("run takes either --pid or a command, not both")
                run(pid=args.pid)
                return 0
            cmd = strip_ddash(args.argv)
            if not cmd:
                parser.error("run needs a command or --pid")
            run(cmd)
            return 0
        if args.pid:
            if strip_ddash(args.argv):
                parser.error("scenario takes either --pid or a command, not both")
            return run_scenario(load_scenario(args.file), pid=args.pid)
        cmd = strip_ddash(args.argv)
        if not cmd:
            parser.error("scenario needs a command or --pid")
        return run_scenario(load_scenario(args.file), cmd)
    except PermissionError as exc:
        sys.exit(
            f"hisstrace: {exc}\n"
            "attach was refused: under kernel.yama.ptrace_scope you may trace your own\n"
            "descendant processes (or run as root). Your shell's other children are off limits."
        )
    except KeyboardInterrupt:
        return 130  # attached traces end with Ctrl-C; the tracee was detached above


if __name__ == "__main__":
    sys.exit(main())
