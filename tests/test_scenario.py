import errno
import os
import subprocess
import sys
import tempfile
import time
import unittest

from hisstrace import current
from hisstrace.scenario import (
    DEFAULT_NAMES,
    Args,
    Call,
    CompletedCall,
    Matcher,
    any_of,
    arg_names,
    load,
    on,
    post,
    pre,
    run,
)


class MatcherTest(unittest.TestCase):
    def test_unknown_syscall(self):
        with self.assertRaises(ValueError):
            Matcher("entry", "not_a_syscall", {})

    def test_unknown_filter(self):
        with self.assertRaises(ValueError):
            Matcher("entry", "write", {"nosucharg": 1})

    def test_filter_on_unspecd_syscall(self):
        with self.assertRaises(ValueError):
            Matcher("entry", "execve", {"fd": 1})

    def test_matcher_awaitable(self):
        matcher = Matcher("entry", "write", {})
        self.assertEqual(matcher.phase, "entry")
        self.assertEqual(matcher.number, current().names["write"])


class ArgsTest(unittest.TestCase):
    def test_named_access(self):
        args = Args(("fd", "buf", "count"), (1, 4096, 5))
        self.assertEqual(args.fd, 1)
        self.assertEqual(args.buf, 4096)
        self.assertEqual(args.count, 5)
        self.assertEqual(args.raw, (1, 4096, 5))

    def test_unknown_name(self):
        with self.assertRaises(AttributeError):
            Args((), ()).fd


class CompletedCallTest(unittest.TestCase):
    def test_error_helpers(self):
        ok = CompletedCall(1, "write", Args((), ()), 5)
        self.assertTrue(ok.succeeded)
        self.assertFalse(ok.failed)
        self.assertIsNone(ok.error)
        fail = CompletedCall(1, "write", Args((), ()), (1 << 64) - errno.EBADF)
        self.assertTrue(fail.failed)
        self.assertEqual(fail.error, errno.EBADF)


class ScenarioRunTest(unittest.TestCase):
    def test_post_write_captures_data(self):
        got = []

        async def scenario():
            got.append(await post.write())

        status = run(scenario, [sys.executable, "-c", "import os; os.write(1, b'hello')"])
        self.assertEqual(status, 0)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].retval, 5)
        self.assertEqual(got[0].data, b"hello")

    def test_pre_write_captures_data(self):
        got = []

        async def scenario():
            got.append(await pre.write(fd=1))

        status = run(scenario, [sys.executable, "-c", "import os; os.write(1, b'hello')"])
        self.assertEqual(status, 0)
        self.assertEqual(got[0].args.fd, 1)
        self.assertEqual(got[0].data, b"hello")

    def test_read_then_write(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"hisstrace-test-data\n")
            path = f.name
        self.addCleanup(os.unlink, path)
        got = []

        async def scenario():
            got.append(await post.read(count=1000))  # startup reads have other counts
            got.append(await pre.write(fd=1))

        child = f"import os; fd = os.open({path!r}, os.O_RDONLY); os.write(1, os.read(fd, 1000))"
        status = run(scenario, [sys.executable, "-c", child])
        self.assertEqual(status, 0)
        read, write = got
        self.assertEqual(read.data, b"hisstrace-test-data\n")
        self.assertEqual(read.retval, len(read.data))
        self.assertEqual(write.data, b"hisstrace-test-data\n")

    def test_scenario_return_passes_through(self):
        got = []

        async def scenario():
            got.append(await post.write())
            return  # tracee keeps running untraced from here

        child = "import os; os.write(1, b'one'); os.write(1, b'two')"
        status = run(scenario, [sys.executable, "-c", child])
        self.assertEqual(status, 0)
        self.assertEqual(len(got), 1)  # the second write passed through unmatched

    def test_pre_and_post_of_same_syscall_in_any_of(self):
        # an entry event must still be recorded for the exit-phase branch even
        # when an entry-phase branch consumes it, or the exit never correlates
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"x" * 2000)
            path = f.name
        self.addCleanup(os.unlink, path)
        got = []

        async def scenario():
            while len(got) < 4:
                got.append(await any_of(pre.read(count=1000), post.read(count=1000)))

        child = f"import os; fd = os.open({path!r}, os.O_RDONLY); os.read(fd, 1000); os.read(fd, 1000)"
        status = run(scenario, [sys.executable, "-c", child])
        self.assertEqual(status, 0)
        entries = [e for e in got if isinstance(e, Call)]
        exits = [e for e in got if isinstance(e, CompletedCall)]
        self.assertEqual(len(entries), 2)
        self.assertEqual(len(exits), 2)
        self.assertEqual([e.retval for e in exits], [1000, 1000])

    def test_alternating_pre_then_post_collects_exits(self):
        # awaiting pre.read then post.read for the same in-flight call must
        # still deliver the exit: the entry is consumed by the pre-branch, so
        # the dispatcher must have recorded it for the post-branch
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"y" * 1500)
            path = f.name
        self.addCleanup(os.unlink, path)
        got = []

        async def scenario():
            fd = None
            while fd is None:  # pointer filters compare raw values; match the string
                opened = await post.openat()
                if opened.string("path") == path:
                    fd = opened.retval
            for _ in range(2):
                await pre.read(fd=fd, count=750)
                got.append(await post.read(fd=fd))
            await pre.close(fd=fd)

        child = f"import os; fd = os.open({path!r}, os.O_RDONLY); os.read(fd, 750); os.read(fd, 750)"
        status = run(scenario, [sys.executable, "-c", child])
        self.assertEqual(status, 0)
        self.assertEqual([e.retval for e in got], [750, 750])
        self.assertTrue(all(e.data == b"y" * 750 for e in got))

    def test_overwrite_shrinks_the_next_call(self):
        # overwrite on a pre-match rewrites argument registers before the
        # kernel runs the call; the post-match sees the shrunk request
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"z" * 100)
            path = f.name
        self.addCleanup(os.unlink, path)
        got = []

        async def scenario():
            fd = None
            while fd is None:
                opened = await post.openat()
                if opened.string("path") == path:
                    fd = opened.retval
            call = await pre.read(fd=fd, count=100)
            call.overwrite(count=1)
            got.append(await post.read(fd=fd))
            await pre.close(fd=fd)

        child = f"import os; fd = os.open({path!r}, os.O_RDONLY); os.read(fd, 100)"
        status = run(scenario, [sys.executable, "-c", child])
        self.assertEqual(status, 0)
        self.assertEqual(got[0].retval, 1)
        self.assertEqual(got[0].data, b"z")
        self.assertEqual(got[0].args.count, 1)  # the match view is refreshed


class AnyOfTest(unittest.TestCase):
    def test_requires_matchers(self):
        with self.assertRaises(ValueError):
            any_of()

    def test_rejects_non_matchers(self):
        with self.assertRaises(TypeError):
            any_of(pre.write(), "nope")

    def test_tracks_fd_until_close(self):
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC  # what os.open really passes
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            path = f.name
        self.addCleanup(os.unlink, path)
        got = []

        async def scenario():
            opened = await post.openat(flags=flags)
            fd = opened.retval
            while True:
                event = await any_of(post.read(fd=fd), pre.write(fd=fd), pre.close(fd=fd))
                got.append(event)
                if event.name == "close":
                    break

        child = (
            f"import os; fd = os.open({path!r}, {flags}); os.write(fd, b'aaa'); "
            "os.lseek(fd, 0, 0); os.read(fd, 3); os.close(fd); os.write(1, b'after')"
        )
        status = run(scenario, [sys.executable, "-c", child])
        self.assertEqual(status, 0)
        self.assertEqual([e.name for e in got], ["write", "read", "close"])
        self.assertIsInstance(got[0], Call)  # pre.write
        self.assertIsInstance(got[1], CompletedCall)  # post.read
        self.assertEqual(got[0].data, b"aaa")
        self.assertEqual(got[1].data, b"aaa")
        self.assertEqual(got[1].retval, 3)

    def test_repeated_events_of_same_type(self):
        got = []

        async def scenario():
            for _ in range(2):
                got.append(await any_of(post.write(fd=1), pre.close(fd=1)))

        status = run(scenario, [sys.executable, "-c", "import os; os.write(1, b'a'); os.write(1, b'b')"])
        self.assertEqual(status, 0)
        self.assertEqual([e.data for e in got], [b"a", b"b"])

    def test_writes_across_threads(self):
        got = []

        async def scenario():
            while len(got) < 2:
                got.append(await post.write(fd=1))

        child = (
            "import os, threading; "
            "t = threading.Thread(target=os.write, args=(1, b'T')); "
            "t.start(); os.write(1, b'M'); t.join()"
        )
        status = run(scenario, [sys.executable, "-c", child])
        self.assertEqual(status, 0)
        self.assertEqual({d.data for d in got}, {b"T", b"M"})
        self.assertEqual(len({d.tid for d in got}), 2)  # correlated per thread


class ChildFollowTest(unittest.TestCase):
    CHILD = "import os, sys; pid = os.fork(); os.write(1, b'P' if pid else b'C'); sys.exit(0)"

    def test_follow(self):
        got = []

        async def scenario():
            child = await on.fork()
            child.follow()
            while len(got) < 2:
                got.append(await post.write(fd=1))

        status = run(scenario, [sys.executable, "-c", self.CHILD])
        self.assertEqual(status, 0)
        self.assertEqual({d.data for d in got}, {b"P", b"C"})
        self.assertEqual(len({d.pid for d in got}), 2)

    def test_no_follow_by_default(self):
        got = []

        async def scenario():
            await on.fork()  # no follow(): the child runs untraced
            got.append(await post.write(fd=1))

        status = run(scenario, [sys.executable, "-c", self.CHILD])
        self.assertEqual(status, 0)
        self.assertEqual([d.data for d in got], [b"P"])  # only the traced parent

    def test_unawaited_fork_passes_through(self):
        got = []

        async def scenario():
            got.append(await post.write(fd=1))  # no on.fork() await at all

        status = run(scenario, [sys.executable, "-c", self.CHILD])
        self.assertEqual(status, 0)
        self.assertEqual([d.data for d in got], [b"P"])

    def test_fork_no_filters_yet(self):
        with self.assertRaises(ValueError):
            on.fork(parent=1)


class AnyMatcherTest(unittest.TestCase):
    def test_any_rejects_filters(self):
        with self.assertRaises(ValueError):
            Matcher("entry", "any", {"fd": 1})

    def test_post_any_captures_everything(self):
        got = []

        async def scenario():
            while "write" not in {d.name for d in got}:
                got.append(await post.any())

        status = run(scenario, [sys.executable, "-c", "import os; os.write(1, b'x')"])
        self.assertEqual(status, 0)
        self.assertGreater(len(got), 5)
        for done in got:
            self.assertIsInstance(done, CompletedCall)
            self.assertEqual(len(done.args.raw), 6)
            self.assertTrue(done.succeeded or done.failed)

    def test_pre_any_stops_everything(self):
        got = []

        async def scenario():
            while not any(c.name == "write" for c in got):
                got.append(await pre.any())

        status = run(scenario, [sys.executable, "-c", "import os; os.write(1, b'x')"])
        self.assertEqual(status, 0)
        write = next(c for c in got if c.name == "write")
        self.assertEqual(write.args.fd, 1)


class ArgNamesTest(unittest.TestCase):
    def test_generated_names(self):
        self.assertEqual(arg_names("read")[:3], ("fd", "buf", "count"))
        self.assertEqual(arg_names("openat"), ("dirfd", "path", "flags", "mode"))
        self.assertEqual(arg_names("socket"), ("domain", "type", "protocol"))

    def test_unknown_falls_back(self):
        self.assertEqual(arg_names("not_a_syscall"), DEFAULT_NAMES)

    def test_args_on_completed_call(self):
        done = CompletedCall(1, "mmap", Args(arg_names("mmap"), (0, 100, 3, 34, 4, 0)), 99)
        self.assertEqual(done.args.len, 100)
        self.assertEqual(done.args.prot, 3)


class StringArgTest(unittest.TestCase):
    def test_openat_path(self):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        got = []

        async def scenario():
            call = await pre.openat(flags=flags)
            got.append(call.string("path"))

        child = f"import os; os.open('/etc/hostname', {flags})"
        status = run(scenario, [sys.executable, "-c", child])
        self.assertEqual(status, 0)
        self.assertEqual(got, ["/etc/hostname"])


class AttachRunTest(unittest.TestCase):
    def test_attach_capture(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import os, time\nwhile True:\n    os.write(1, b'x')\n    time.sleep(0.05)"],
            stdout=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.5)  # let the child finish Python startup
            got = []

            async def scenario():
                got.append(await post.write(fd=1))

            status = run(scenario, pid=proc.pid)
            self.assertEqual(status, 0)  # attach mode: no exit status to report
            self.assertEqual(got[0].data, b"x")
        finally:
            proc.kill()
            proc.wait()


class LoadTest(unittest.TestCase):
    def write_scenario(self, body):
        f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        f.write(body)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_load_and_run(self):
        path = self.write_scenario("from hisstrace import post\n\n\nasync def scenario():\n    await post.write()\n")
        scenario = load(path)
        status = run(scenario, [sys.executable, "-c", "import os; os.write(1, b'x')"])
        self.assertEqual(status, 0)

    def test_load_requires_scenario(self):
        path = self.write_scenario("x = 1\n")
        with self.assertRaises(ValueError):
            load(path)


if __name__ == "__main__":
    unittest.main()
