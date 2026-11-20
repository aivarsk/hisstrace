"""Ordered awaits as assertions: the file-spill conversation.

Traces a child that writes a large buffer to a fresh file in /tmp and
unlinks it, and asserts on the syscall chain in the order it happens:

  1. the file opens in /tmp with O_CREAT|O_EXCL
  2. the whole payload is written
  3. the file is closed and unlinked

Usage: hisstrace scenario examples/chain_assert.py -- python3 -c "..."
(or let the built-in child do it: no -- command needed)

The point: a chain of awaits reads like the story of the transfer, and
each line fails the scenario at the exact step where reality diverged.
"""

import json
import os
import sys
import tempfile

from hisstrace import post, run

CHILD = r"""
import os, sys, tempfile
payload = b"x" * 200000
path = tempfile.mktemp(prefix="HISS", dir="/tmp")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, payload)
os.close(fd)
os.unlink(path)
"""


async def scenario():
    verdict = {}

    opened = await post.openat(path__contains="/tmp/",
                               flags__bits=os.O_CREAT | os.O_EXCL)
    verdict["opens_in_tmp"] = "ok" if opened.succeeded else f"fail: {opened.error}"

    written = await post.write(count__ge=200000)
    verdict["payload_written"] = "ok" if written.succeeded else "fail"

    closed = await post.close(fd=opened.retval)
    verdict["closed"] = "ok" if closed.succeeded else "fail"

    unlinked = await post.unlink(path__contains="/tmp/")
    verdict["unlinked"] = "ok" if unlinked.succeeded else "fail"

    print("CHAIN " + json.dumps(verdict))


if __name__ == "__main__":
    argv = sys.argv[1:] or [sys.executable, "-c", CHILD]
    status = run(scenario, argv)
    sys.exit(status)
