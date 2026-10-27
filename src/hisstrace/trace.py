"""Trace a process tree through syscall stops and yield events."""

import os
import signal
import time
from dataclasses import dataclass

from . import ptrace
from .arch import current


@dataclass
class Event:
    pid: int  # process (thread group) id
    tid: int  # thread id; equals pid for the main thread
    entry: bool  # True: stopped before the kernel runs the call; False: after
    number: int
    name: str
    args: tuple  # six raw argument registers
    retval: int | None  # exit stops only


@dataclass
class Child:
    """A traced task created a new process.

    The child stays frozen until the consumer decides: follow() traces it,
    drop() (or no call at all) lets it run untraced. Threads are different:
    they are followed automatically and never surface as Child.
    """

    pid: int  # the new process id; its first task's tid
    parent_tid: int  # the task that created it
    vfork: bool = False
    followed: bool = False

    def follow(self):
        self.followed = True

    def drop(self):
        self.followed = False


@dataclass
class Trap:
    """A software breakpoint (int3) fired: the tracee is stopped at addr.

    regs is the raw register block at the trap; single-stepping over the
    replaced instruction and re-arming the breakpoint is already done.
    """

    tid: int
    addr: int
    regs: object


class TraceeExited(Exception):
    def __init__(self, pid, status):
        self.pid = pid
        self.status = status
        if os.WIFEXITED(status):
            message = f"tracee {pid} exited with status {os.WEXITSTATUS(status)}"
        else:
            message = f"tracee {pid} killed by signal {os.WTERMSIG(status)}"
        super().__init__(message)


def signed(value):
    """Interpret an unsigned 64-bit register as signed."""
    return value - (1 << 64) if value >= 1 << 63 else value


class Tracer:
    """Spawn argv under ptrace, or attach to a running pid, and iterate stops.

    Threads are always followed. Child processes surface as Child events:
    the consumer decides each one via follow_child()/drop_child() (the
    scenario runner does this from the scenario's follow() calls, and drops
    unclaimed children automatically). A standalone consumer must decide
    every Child, or that child stays frozen.
    """

    _OPTIONS = (
        ptrace.O_TRACESYSGOOD
        | ptrace.O_TRACEEXEC
        | ptrace.O_TRACEFORK
        | ptrace.O_TRACEVFORK
        | ptrace.O_TRACECLONE
        | ptrace.O_EXITKILL
    )

    def __init__(self, argv=None, attach_pid=None, arch=None):
        if (argv is None) == (attach_pid is None):
            raise ValueError("give exactly one of argv or attach_pid")
        self.arch = arch or current()
        self.argv = argv
        self._at_entry: dict[int, bool] = {}
        self._tgids = {}  # tid -> process id
        self._fresh = set()  # tids whose next stop is the synthetic SIGSTOP of auto-attach
        self._pending_sig = {}  # tid -> real signal to deliver on its next resume
        self._resume: list[int] = []  # stopped tids owed a PTRACE_SYSCALL
        self._undecided = set()  # child processes awaiting a follow/drop decision
        self._child_stopped = set()  # undecided children whose initial stop is consumed
        self._rejected = set()  # dropped children to detach at their initial stop
        self._breakpoints = {}  # addr -> original byte (int3 set)
        self._cleared = set()  # addr once cleared: late in-flight traps are swallowed

        if attach_pid is None:
            self.pid = os.fork()
            if self.pid == 0:
                try:
                    ptrace.ptrace(ptrace.TRACEME, 0)
                    os.execvp(argv[0], argv)
                finally:
                    os._exit(127)
            _, status = os.waitpid(self.pid, 0)
            if not os.WIFSTOPPED(status):
                raise TraceeExited(self.pid, status)
            self._set_options(self.pid)
            self._at_entry[self.pid] = True
            self._tgids[self.pid] = self.pid
            self._resume.append(self.pid)  # exec stop was consumed: leader is due a resume
        else:
            self.pid = attach_pid
            status = 0
            self._attach_tree()  # attaches everything, then starts it all
        self.exit_status = status

    @classmethod
    def attach(cls, pid, arch=None):
        """Trace a running process and all its threads, following new ones."""
        return cls(None, attach_pid=pid, arch=arch)

    def _task_ids(self):
        try:
            return sorted(int(t) for t in os.listdir(f"/proc/{self.pid}/task"))
        except FileNotFoundError:
            raise ProcessLookupError(f"no such process: {self.pid}")

    def exe_image(self):
        """The main executable as bytes (the file /proc/pid/exe links to).
        Useful for byte-signature scans when the binary is stripped."""
        with open(f"/proc/{self.pid}/exe", "rb") as f:
            return f.read()

    def exe_vaddr(self, offset):
        """Runtime virtual address for a file offset in the main executable,
        via /proc/pid/maps. Works for PIE and ET_EXEC alike."""
        exe = os.readlink(f"/proc/{self.pid}/exe")
        with open(f"/proc/{self.pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6 and parts[5] == exe and "x" in parts[1]:
                    start, end = (int(x, 16) for x in parts[0].split("-"))
                    map_off = int(parts[2], 16)
                    if map_off <= offset < map_off + (end - start):
                        return start + (offset - map_off)
        raise ValueError(f"file offset {offset:#x} not in an executable mapping of pid {self.pid}")

    def _attach_tree(self):
        """Attach every existing thread, plus latecomers, until the set is stable."""
        todo = set()

        def attach(tid):
            ptrace.ptrace(ptrace.ATTACH, tid, 0, 0)  # raises: gone, or not permitted
            self._at_entry[tid] = True
            self._tgids[tid] = self.pid
            todo.add(tid)

        def note_creation(tid, event_code):
            new_tid = ptrace.event_msg(tid)
            if event_code == ptrace.EVENT_CLONE and self._is_thread(new_tid, tid):
                self._at_entry[new_tid] = True
                self._tgids[new_tid] = self._tgids[tid]
                todo.add(new_tid)  # its synthetic SIGSTOP will follow
            else:
                self._undecided.add(new_tid)

        attach(self.pid)
        for _ in range(16):
            for tid in self._task_ids():
                if tid not in self._at_entry:
                    try:
                        attach(tid)
                    except OSError:
                        pass  # died between listing and attach
            while todo:
                tid, status = ptrace.wait_wall()
                todo.discard(tid)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    self._drop(tid)
                elif status >> 16 in (ptrace.EVENT_CLONE, ptrace.EVENT_FORK, ptrace.EVENT_VFORK):
                    note_creation(tid, status >> 16)
                else:
                    self._set_options(tid)
            if all(t in self._at_entry for t in self._task_ids()):
                break
        # pathological spawn rate: keep what we attached; TRACECLONE covers the rest
        for tid in list(self._at_entry):  # drained and stopped: start them all
            try:
                ptrace.ptrace(ptrace.SYSCALL, tid, 0, 0)
            except ProcessLookupError:
                self._drop(tid)

    def _set_options(self, tid):
        ptrace.ptrace(ptrace.SETOPTIONS, tid, 0, self._OPTIONS)

    def _with_live_task(self, op):
        """Run op(tid) on each traced task until one succeeds. The leader may
        have exited already (Go retires idle OS threads), so the first entry
        is not necessarily alive. Call with tracees stopped."""
        last = None
        for tid in list(self._at_entry):
            try:
                return op(tid)
            except OSError as exc:
                last = exc
        raise last or ProcessLookupError("no live traced task")

    def clear_breakpoint(self, addr):
        """Remove an int3, restoring the original byte. Call with tracees stopped."""
        original = self._breakpoints.pop(addr, None)
        if original is not None:
            self._cleared.add(addr)
            self._with_live_task(lambda tid: ptrace.poke(tid, addr, original))

    def set_breakpoint(self, addr):
        """Arm an int3 at addr; fires as a Trap event. Call with tracees stopped."""

        def arm(tid):
            if addr not in self._breakpoints:
                self._breakpoints[addr] = ptrace.peek(tid, addr, 1)
            ptrace.poke(tid, addr, b"\xcc")

        self._with_live_task(arm)

    def _breakpoint_hit(self, tid):
        """Handle a SIGTRAP from one of our int3s. Returns a Trap to deliver,
        True when a late trap from a cleared breakpoint was swallowed (the
        byte is the restored instruction again: rewind the PC and let it
        re-execute), None when the SIGTRAP is genuine and must be delivered."""
        try:
            regs = self.arch.get(tid)
        except OSError:
            return None
        addr = self.arch.pc(regs) - 1
        if addr not in self._breakpoints:
            if addr not in self._cleared:
                return None
            self.arch.set_pc(regs, addr)
            self.arch.set(tid, regs)
            self._resume.append(tid)
            return True
        try:
            self.arch.set_pc(regs, addr)  # int3 leaves rip past the trap; step the whole instruction
            self.arch.set(tid, regs)
            ptrace.poke(tid, addr, self._breakpoints[addr])  # restore the instruction
            ptrace.ptrace(ptrace.SINGLESTEP, tid, 0, 0)
            status = ptrace.wait_tid(tid)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                raise ProcessLookupError(tid)
            ptrace.poke(tid, addr, b"\xcc")  # re-arm
        except OSError:  # task died mid-handling; restore the byte via any live task
            live = next(iter(self._at_entry), None) or self.pid
            try:
                ptrace.poke(live, addr, self._breakpoints[addr])
            except OSError:
                pass
            self._drop(tid)
            return None
        self._resume.append(tid)
        return Trap(tid=tid, addr=addr, regs=regs)

    def _is_thread(self, new_tid, cloner_tid):
        """True when the created task joined the cloner's thread group."""
        try:
            with open(f"/proc/{new_tid}/status") as f:
                for line in f:
                    if line.startswith("Tgid:"):
                        return int(line.split()[1]) == self._tgids.get(cloner_tid)
        except OSError:
            pass
        return False

    def follow_child(self, tid):
        """Trace a created process the consumer accepted."""
        if tid not in self._undecided:
            return
        self._undecided.discard(tid)
        self._at_entry[tid] = True
        self._tgids[tid] = tid
        if tid in self._child_stopped:  # initial stop consumed: set up and run
            self._child_stopped.discard(tid)
            self._set_options(tid)
            self._resume.append(tid)
        else:  # the SIGSTOP is still pending: the fresh path handles it
            self._fresh.add(tid)

    def drop_child(self, tid):
        """Let a created process run untraced."""
        if tid not in self._undecided:
            return
        self._undecided.discard(tid)
        if tid in self._child_stopped:  # stopped with its stop consumed: detach now
            self._child_stopped.discard(tid)
            try:
                ptrace.ptrace(ptrace.DETACH, tid, 0, 0)
            except OSError:
                pass
        else:
            self._rejected.add(tid)  # detach when its initial stop arrives

    def _drop(self, tid):
        self._at_entry.pop(tid, None)
        self._tgids.pop(tid, None)
        self._fresh.discard(tid)
        self._pending_sig.pop(tid, None)
        self._undecided.discard(tid)
        self._child_stopped.discard(tid)
        self._rejected.discard(tid)

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            while self._resume:
                tid = self._resume.pop(0)
                sig = self._pending_sig.pop(tid, 0)
                try:
                    ptrace.ptrace(ptrace.SYSCALL, tid, 0, sig)
                except ProcessLookupError:
                    pass  # died while stopped; its exit surfaces through waitpid
            tid, status = ptrace.wait_wall()
            self.exit_status = status
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                self._drop(tid)
                if not self._at_entry and not self._undecided:
                    raise StopIteration
                continue
            event_code = status >> 16
            if event_code == ptrace.EVENT_EXEC:
                self._resume.append(tid)
                continue  # post-exec trap (from O_TRACEEXEC): swallow, never deliver
            if event_code in (ptrace.EVENT_CLONE, ptrace.EVENT_FORK, ptrace.EVENT_VFORK):
                new_tid = ptrace.event_msg(tid)
                if event_code == ptrace.EVENT_CLONE and self._is_thread(new_tid, tid):
                    self._at_entry[new_tid] = True
                    self._tgids[new_tid] = self._tgids[tid]
                    self._fresh.add(new_tid)
                else:  # a new process: park it for a follow/drop decision
                    self._undecided.add(new_tid)
                    self._resume.append(tid)
                    return Child(pid=new_tid, parent_tid=tid, vfork=event_code == ptrace.EVENT_VFORK)
                self._resume.append(tid)
                continue
            sig = os.WSTOPSIG(status)
            if sig != signal.SIGTRAP | ptrace.SIGTRAP_SYSGOOD:
                if sig == signal.SIGTRAP and (self._breakpoints or self._cleared):
                    hit = self._breakpoint_hit(tid)
                    if isinstance(hit, Trap):
                        return hit  # restore/step/re-arm already done
                    if hit:
                        continue  # late trap from a cleared breakpoint: swallowed
                if tid in self._rejected:
                    self._rejected.discard(tid)
                    self._detach(tid)
                    continue  # never followed: let it run free
                if tid in self._undecided:
                    self._child_stopped.add(tid)  # parked until the consumer decides
                    continue
                if sig == signal.SIGSTOP and tid in self._fresh:
                    self._fresh.discard(tid)
                    self._set_options(tid)
                    self._resume.append(tid)
                    continue  # synthetic stop from auto-attach: swallow
                self._pending_sig[tid] = sig  # real signal: deliver on its next resume
                self._resume.append(tid)
                continue
            regs = self.arch.get(tid)
            if tid not in self._at_entry:
                # creation event lost to stop coalescing; the -ENOSYS marker still places the stop
                self._at_entry[tid] = True
                self._tgids.setdefault(tid, self.pid)
            number = self.arch.number(regs)
            retval = self.arch.retval(regs)
            if self.arch.machine == "x86_64":
                # entry stops carry -ENOSYS in the return register; restarted
                # syscalls re-report entry, so a plain toggle would desync
                at_entry = retval == (1 << 64) - 38  # -ENOSYS
            else:
                at_entry = self._at_entry[tid]
                self._at_entry[tid] = not at_entry
            event = Event(
                pid=self._tgids[tid],
                tid=tid,
                entry=at_entry,
                number=number,
                name=self.arch.syscall_name(number),
                args=self.arch.args(regs),
                retval=None if at_entry else retval,
            )
            self._resume.append(tid)
            return event

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def _detach(self, tid):
        try:
            ptrace.ptrace(ptrace.DETACH, tid, 0, 0)
            return True
        except OSError:
            return False  # gone, or running (ptrace refuses to detach a running task)

    def close(self):
        """Detach every traced task that is still alive, decided or not.

        Stopped tasks detach directly; running ones are stopped first. A
        SIGSTOP also group-stops the process, so the last detached task gets
        a SIGCONT to release the rest. Tasks that never stop (uninterruptible
        sleep) are left for O_EXITKILL once the tracer exits.
        """
        self._resume.clear()
        for tid in list(self._rejected):  # pending initial stop would freeze them
            try:
                ptrace.wait_tid(tid)
            except (ChildProcessError, ProcessLookupError):
                pass
        wake = None
        for tid in list(self._at_entry) + list(self._undecided) + list(self._rejected):
            if self._detach(tid):
                wake = tid
                continue
            try:
                os.kill(tid, signal.SIGSTOP)  # stop it, then detach
            except OSError:
                continue  # dead or gone
            for _ in range(200):  # ~2s: uninterruptible sleep ignores SIGSTOP
                if ptrace.wait_tid_nohang(tid) is not None:
                    break
                time.sleep(0.01)
            if self._detach(tid):
                wake = tid
        if wake is not None:
            try:
                os.kill(wake, signal.SIGCONT)  # release the group stop the SIGSTOPs caused
            except OSError:
                pass
