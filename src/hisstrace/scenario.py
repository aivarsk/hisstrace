"""Coroutine scenario API: pre/post matchers plus the runtime driving them.

One scenario coroutine runs at a time, serially. While Python code between
awaits runs, the matched tracee stays stopped; reaching the next await resumes
it. Unmatched syscalls pass through unchanged. When the coroutine returns,
tracing continues pass-through until the tracee exits; a tracee exit ends the
scenario silently.
"""

import importlib.util
import inspect
import os
from dataclasses import dataclass, field

from . import ptrace
from .arch import current
from .table import ARGS as ARG_NAMES
from .trace import Child, Event, Tracer, Trap, signed

MAX_DATA = 1 << 20  # buffer snapshots are capped at 1 MiB
DEFAULT_NAMES = tuple(f"arg{i}" for i in range(6))  # for syscalls missing from ARGS

_active_tracer = None


def tracer():
    """The Tracer driving the current scenario; None outside run()."""
    return _active_tracer


def arg_names(syscall_name):
    return ARG_NAMES.get(syscall_name, DEFAULT_NAMES)


class Args:
    """Named view over the six raw argument registers."""

    def __init__(self, names, values):
        self.raw = tuple(values)
        self._map = dict(zip(names, values))

    def __getattr__(self, name):
        try:
            return self._map[name]
        except KeyError:
            raise AttributeError(name) from None

    def __repr__(self):
        return f"Args({', '.join(f'{k}={v}' for k, v in self._map.items())})"


def _errno(retval):
    value = signed(retval)
    return -value if -4095 <= value <= -1 else None


class _Match:
    """Common ground for matches: identity, named args, tracee string reads."""

    def __init__(self, pid, name, args, tid):
        self.pid = pid
        self.tid = tid if tid is not None else pid
        self.name = name
        self.args = args

    def string(self, name):
        """Read a C string from the tracee at the named pointer argument."""
        return ptrace.peek_cstring(self.tid, getattr(self.args, name))


class Call(_Match):
    """A pre-call match: the tracee is stopped at syscall entry."""

    def __init__(self, pid, name, args, data=None, tid=None, number=0):
        super().__init__(pid, name, args, tid)
        self.data = data
        self._number = number  # for run() to sync overwrites into pending
        self._new_args = None

    def overwrite(self, **args):
        """Rewrite arguments before the kernel runs the call, by name.

        The tracee is stopped at entry; values land in the argument
        registers, this match's args view is refreshed, and the pending
        entry is updated so the matching post-match sees the new values.
        """
        arch = current()
        names = arg_names(self.name)
        for key in args:
            if key not in names:
                raise ValueError(f"{self.name}() has no argument {key!r}")
        regs = arch.get(self.tid)
        raw = list(self.args.raw)
        for key, value in args.items():
            index = names.index(key)
            arch.set_arg(regs, index, value)
            raw[index] = value
        arch.set(self.tid, regs)
        self.args = Args(names, raw)
        self._new_args = tuple(raw)

    def __repr__(self):
        return f"Call({self.name}, {self.args!r})"


class CompletedCall(_Match):
    """A post-call match: the entry snapshot plus the real result."""

    def __init__(self, pid, name, args, retval, data=None, tid=None):
        super().__init__(pid, name, args, tid)
        self.retval = retval
        self.data = data

    @property
    def error(self):
        """The errno number, or None when the call succeeded."""
        return _errno(self.retval)

    @property
    def succeeded(self):
        return self.error is None

    @property
    def failed(self):
        return self.error is not None

    def __repr__(self):
        return f"CompletedCall({self.name}, retval={self.retval})"


@dataclass(eq=False)
class Matcher:
    """An awaited syscall match; resumes the scenario with its result."""

    phase: str  # "entry" for pre, "exit" for post, "child" for on.fork()
    name: str
    filters: dict = field(default_factory=dict)
    number: int = field(init=False)
    _checks: tuple = field(init=False, repr=False)

    def __post_init__(self):
        if self.phase == "child":  # process-creation events, not a syscall match
            if self.filters:
                raise ValueError(f"on.{self.name}() takes no filters yet")
            self.number = -1
            self._checks = ()
            return
        if self.name == "any":  # wildcard: match every syscall in this phase
            if self.filters:
                raise ValueError("any() takes no filters")
            self.number = -1
            self._checks = ()
            return
        arch = current()
        if self.name not in arch.names:
            raise ValueError(f"unknown syscall for {arch.machine}: {self.name}")
        self.number = arch.names[self.name]
        names = arg_names(self.name)
        for key in self.filters:
            if key not in names:
                raise ValueError(f"{self.name}() has no argument {key!r}")
        self._checks = tuple((names.index(key), value) for key, value in self.filters.items())

    def matches(self, event):
        if self.name == "any":
            return True
        return event.number == self.number and all(event.args[i] == v for i, v in self._checks)

    def __await__(self):
        result = yield self
        return result


class AnyOf:
    """Awaits several matchers; resumes the scenario with whichever matches first."""

    def __init__(self, *matchers):
        if not matchers:
            raise ValueError("any_of() needs at least one matcher")
        for matcher in matchers:
            if not isinstance(matcher, Matcher):
                raise TypeError(f"any_of() takes matchers, got {matcher!r}")
        self.matchers = matchers

    def __await__(self):
        result = yield self
        return result


def any_of(*matchers):
    return AnyOf(*matchers)


class _Phase:
    """Matcher factories: pre.write(...) and post.read(...) by phase, on.fork(...) for creations."""

    def __init__(self, phase):
        self.phase = phase

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def match(**filters):
            return Matcher(self.phase, name, filters)

        return match


pre = _Phase("entry")
post = _Phase("exit")
on = _Phase("child")


# syscalls whose (buf, count) arguments we snapshot; all share the layout
BUFFERED = ("read", "write", "recv", "send", "recvfrom", "sendto")


def _snapshot(pid, name, args, retval=None):
    """Buffer data for read/write and send/recv style calls, read while the tracee is stopped."""
    if name not in BUFFERED:
        return None
    count = args[2]
    if retval is not None:
        if signed(retval) <= 0:
            return b""
        count = min(count, retval)
    return ptrace.peek(pid, args[1], min(count, MAX_DATA))


def _resume(coro, value):
    try:
        return coro.send(value)
    except StopIteration:
        return None


def _dispatch(branches, event, pending):
    """Match one event against the awaited branches.

    Returns the Call/CompletedCall/Child to deliver to the scenario, or None
    when no branch consumed the event. Post (exit-phase) branches record
    matching entries in `pending` keyed by (syscall number, tid); the exit of
    the same task completes the correlation even when the scenario has
    advanced to a new await in between, as long as the current branch still
    matches.
    """
    if isinstance(event, Child):
        return event if any(branch.phase == "child" for branch in branches) else None
    if event.entry:
        # record every consumed entry: a later await may be the exit-phase
        # branch of this same call (pre-then-post alternation), and its exit
        # can only correlate through pending
        if any(branch.phase != "child" and branch.matches(event) for branch in branches):
            pending[(event.number, event.tid)] = event
    for branch in branches:
        if branch.phase == "child":
            continue
        if branch.phase == "entry":
            if event.entry and branch.matches(event):
                call = Call(
                    event.pid,
                    event.name,
                    Args(arg_names(event.name), event.args),
                    tid=event.tid,
                    number=event.number,
                )
                call.data = _snapshot(event.tid, event.name, event.args)
                return call
        elif not event.entry:
            key = event.number if branch.name == "any" else branch.number
            entry = pending.get((key, event.tid))
            if entry is not None and branch.matches(entry):
                pending.pop((key, event.tid))
                completed = CompletedCall(
                    entry.pid, entry.name, Args(arg_names(entry.name), entry.args), event.retval, tid=entry.tid
                )
                completed.data = _snapshot(entry.tid, entry.name, entry.args, retval=event.retval)
                return completed
    return None


def run(scenario, argv=None, pid=None):
    """Drive one scenario coroutine; against argv spawned, or pid attached.

    Returns the tracee exit status for spawned commands, 0 when attaching.
    When the coroutine returns, tracing stops and the tracee is detached.
    """
    if (argv is None) == (pid is None):
        raise ValueError("give exactly one of argv or pid")
    arch = current()
    coro = scenario if inspect.iscoroutine(scenario) else scenario()
    with Tracer(argv, attach_pid=pid, arch=arch) as tracer:
        global _active_tracer
        _active_tracer = tracer
        matcher = _resume(coro, None)
        pending: dict[tuple[int, int], Event] = {}  # (syscall number, tid) -> entry event
        for event in tracer:
            if isinstance(event, Trap):
                if matcher is not None:
                    matcher = _resume(coro, event)  # a trap does not consume the await
                continue
            if matcher is None:
                if pid is not None:
                    break  # attached: scenario done, detach and return
                continue  # spawned: pass through until the tracee exits
            if isinstance(matcher, Matcher):
                branches = (matcher,)
            elif isinstance(matcher, AnyOf):
                branches = matcher.matchers
            else:
                raise TypeError(f"scenario awaited a non-hisstrace object: {matcher!r}")
            result = _dispatch(branches, event, pending)
            if result is None:
                if isinstance(event, Child):
                    tracer.drop_child(event.pid)  # nobody asked: let it run free
                continue
            matcher = _resume(coro, result)
            if isinstance(result, Call) and result._new_args is not None:
                entry = pending.get((result._number, result.tid))
                if entry is not None:
                    entry.args = result._new_args  # overwrite() reached the post-match too
            if isinstance(result, Child):  # the scenario decided during the resume
                if result.followed:
                    tracer.follow_child(result.pid)
                else:
                    tracer.drop_child(result.pid)
        _active_tracer = None
    if pid is not None:
        return 0  # attached processes are not ours to reap or grade
    while True:  # reap the detached leader, skipping stop transitions
        try:
            _, status = os.waitpid(tracer.pid, 0)
        except ChildProcessError:
            break  # already reaped by the trace loop
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            tracer.exit_status = status
            break
    return tracer.exit_status


def load(path):
    """Load a scenario module from a .py file; it must define scenario()."""
    spec = importlib.util.spec_from_file_location("hisstrace_scenario", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load scenario: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    scenario = getattr(module, "scenario", None)
    if not callable(scenario):
        raise ValueError(f"{path} must define scenario()")
    return scenario
