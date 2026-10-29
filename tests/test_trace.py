import errno
import os
import subprocess
import sys
import time
import unittest

from hisstrace.arch import current
from hisstrace.scenario import pre
from hisstrace.scenario import run as run_scenario
from hisstrace.trace import Child, Event, TraceeExited, Tracer, signed


class TraceTest(unittest.TestCase):
    def collect(self, argv):
        with Tracer(argv) as tracer:
            return list(tracer)

    def test_python_child(self):
        events = self.collect([sys.executable, "-c", "import os; os.write(1, b'hi')"])
        names = [e.name for e in events]
        self.assertTrue(events[0].entry)
        self.assertIn("write", names)
        self.assertIn("exit_group", names)

    def test_entry_exit_pairs(self):
        events = self.collect([sys.executable, "-c", "pass"])
        for before, after in zip(events, events[1:]):
            self.assertNotEqual(before.entry, after.entry)  # strictly alternating
            if not after.entry:
                self.assertEqual(before.number, after.number)  # exit belongs to its entry

    def test_exit_retval(self):
        events = self.collect([sys.executable, "-c", "import os; os.write(4194303, b'x')"])
        arch = current()
        write_nr = next(n for n, name in arch.syscalls.items() if name == "write")
        exit = next(e for e in events if not e.entry and e.number == write_nr)
        self.assertEqual(signed(exit.retval), -errno.EBADF)

    def test_reexec(self):
        # A tracee that execs again mid-run (shims, wrappers): tracing must
        # survive the second image and its post-exec trap must not be delivered.
        child = "import os, sys; os.execv(sys.executable, [sys.executable, '-c', 'pass'])"
        events = self.collect([sys.executable, "-c", child])
        self.assertIn("execve", [e.name for e in events])
        self.assertIn("exit_group", [e.name for e in events])

    def test_threads_followed(self):
        child = (
            "import os, threading; "
            "t = threading.Thread(target=os.write, args=(1, b'T')); "
            "t.start(); os.write(1, b'M'); t.join()"
        )
        events = self.collect([sys.executable, "-c", child])
        self.assertGreater(len({e.tid for e in events}), 1)  # the thread was traced
        writes = [e for e in events if e.name == "write" and e.entry and e.args[0] == 1]
        self.assertEqual(len(writes), 2)  # one per thread
        # entry/exit stays strictly alternating within each task
        per_tid = {}
        for event in events:
            per_tid.setdefault(event.tid, []).append(event)
        for tid, tid_events in per_tid.items():
            for before, after in zip(tid_events, tid_events[1:]):
                self.assertNotEqual(before.entry, after.entry, f"tid {tid} out of alternation")

    def test_fork_child_event(self):
        # A forked child surfaces as a Child; without follow() its events are
        # not traced, and the parent's stream is unaffected.
        child = "import os, sys; pid = os.fork(); os.write(1, b'P' if pid else b'C'); sys.exit(0)"
        events = []
        with Tracer([sys.executable, "-c", child]) as tracer:
            for event in tracer:
                events.append(event)
                if isinstance(event, Child):
                    self.assertGreater(event.pid, 0)
                    tracer.drop_child(event.pid)
        pids = {e.pid for e in events if isinstance(e, Event)}
        self.assertEqual(pids, {tracer.pid})  # only the parent stayed traced
        writes = [e for e in events if isinstance(e, Event) and e.name == "write" and e.entry and e.args[0] == 1]
        self.assertEqual(len(writes), 1)  # the child's write ran untraced

    def test_exe_image_and_vaddr(self):
        # exe_image exposes the binary for signature scans; exe_vaddr maps a
        # file offset into an executable mapping back to a runtime address.
        with Tracer([sys.executable, "-c", "import time; time.sleep(30)"]) as tracer:
            image = tracer.exe_image()
            self.assertTrue(image.startswith(b"\x7fELF"))
            exe = os.readlink(f"/proc/{tracer.pid}/exe")
            with open(f"/proc/{tracer.pid}/maps") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6 and parts[5] == exe and "x" in parts[1]:
                        start = int(parts[0].split("-")[0], 16)
                        off = int(parts[2], 16)
                        self.assertEqual(tracer.exe_vaddr(off), start)
                        self.assertEqual(tracer.exe_vaddr(off + 0x100), start + 0x100)
                        break


class AttachTest(unittest.TestCase):
    @staticmethod
    def kill(proc):
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    def spawn(self, code, **kw):
        proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.DEVNULL, **kw)
        self.addCleanup(self.kill, proc)
        return proc

    @staticmethod
    def settle(proc):
        time.sleep(0.5)  # let the child finish its Python startup

    def test_requires_exactly_one_target(self):
        with self.assertRaises(ValueError):
            Tracer()

    def test_attach_dead_process(self):
        with self.assertRaises(OSError):
            Tracer.attach(2**22 - 1)

    def test_attach_basic(self):
        proc = self.spawn("import time; time.sleep(30)")
        self.settle(proc)
        try:
            with Tracer.attach(proc.pid) as tracer:
                names = set()
                for i, event in enumerate(tracer):
                    names.add(event.name)
                    if names & {"clock_nanosleep", "nanosleep"} or i >= 500:
                        break
            self.assertTrue(names & {"clock_nanosleep", "nanosleep"}, names)
            self.assertIsNone(proc.poll())  # detach left it running
        finally:
            self.kill(proc)

    def test_attach_threads_spawned_later(self):
        proc = self.spawn(
            "import threading, time\n"
            "for _ in range(10):\n"
            "    threading.Thread(target=time.sleep, args=(30,)).start()\n"
            "    time.sleep(0.1)\n"  # 1s spawn window: attach lands mid-loop
            "time.sleep(30)"
        )
        self.settle(proc)
        try:
            with Tracer.attach(proc.pid) as tracer:
                tids = set()
                for i, event in enumerate(tracer):
                    tids.add(event.tid)
                    if len(tids) > 1 or i >= 2000:
                        break
            self.assertGreater(len(tids), 1)  # threads born after attach were followed
        finally:
            self.kill(proc)

    def test_close_with_running_tracee(self):
        # close() must not wait forever on a tracee that is still running
        # (the SIGSTOP path): it stops it, detaches, and releases the group
        # stop, leaving the process alive.
        from hisstrace import ptrace

        proc = self.spawn("import time\nwhile True: time.sleep(0.05)")
        self.settle(proc)
        try:
            with Tracer.attach(proc.pid) as tracer:
                for event in tracer:
                    break
                # put the leader back in the running state before close()
                ptrace.ptrace(ptrace.SYSCALL, proc.pid, 0, 0)
                tracer._resume.clear()
            time.sleep(0.3)
            self.assertIsNone(proc.poll())  # detached, not killed
        finally:
            self.kill(proc)

    def test_late_trap_from_cleared_breakpoint_is_swallowed(self):
        # A trap already in flight when clear_breakpoint runs must not be
        # delivered to the tracee as a genuine SIGTRAP: the PC is rewound so
        # the restored instruction re-executes, and the trap is swallowed.
        # Stubbed, not live: provoking a trap in the clear window is a race,
        # while the rewind-and-swallow logic must be pinned deterministically.
        class Regs:
            rip = 0x1001

        class Arch:
            def get(self, tid):
                self.regs = Regs()
                return self.regs

            def set(self, tid, regs):
                self.set_tid = tid

            def pc(self, regs):
                return regs.rip

            def set_pc(self, regs, addr):
                regs.rip = addr

        tracer = Tracer.__new__(Tracer)
        tracer.arch = Arch()
        tracer._breakpoints = {}
        tracer._cleared = {0x1000}
        tracer._resume = []
        self.assertIs(tracer._breakpoint_hit(123), True)
        self.assertEqual(tracer.arch.set_tid, 123)
        self.assertEqual(tracer.arch.regs.rip, 0x1000)  # rewound
        self.assertIn(123, tracer._resume)

    def test_genuine_sigtrap_is_delivered(self):
        # a SIGTRAP that is not one of our int3s belongs to the tracee: the
        # tracer must pass it through, untouched and unstopped
        async def scenario():
            await pre.exit_group()

        child = (
            "import signal, sys\n"
            "def ontrap(signum, frame): sys.exit(42)\n"
            "signal.signal(signal.SIGTRAP, ontrap)\n"
            "signal.raise_signal(signal.SIGTRAP)\n"
        )
        status = run_scenario(scenario, [sys.executable, "-c", child])
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 42)


class ExecFailureTest(unittest.TestCase):
    def test_missing_command(self):
        with self.assertRaises(TraceeExited):
            Tracer(["/definitely/not/a/command"])


class PrinterTest(unittest.TestCase):
    def test_run_printer_output(self):
        # `hisstrace run` is a scenario too: cli.run prints every syscall
        # with named args and results for a spawned command
        import contextlib
        import io

        from hisstrace import cli

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = cli.run([sys.executable, "-c", "import os; os.write(1, b'hi')"])
        self.assertEqual(status, 0)
        lines = out.getvalue()
        self.assertIn("write(fd=1", lines)
        self.assertIn(") = 2", lines)
        self.assertIn("brk(", lines)


if __name__ == "__main__":
    unittest.main()
