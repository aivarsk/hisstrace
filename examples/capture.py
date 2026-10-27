"""Print the data buffer of one read, then of the next write.

    hisstrace scenario examples/capture.py -- python3 -c \
        "import os; fd = os.open('/etc/hostname', os.O_RDONLY); os.write(1, os.read(fd, 100))"
"""

from hisstrace import post, pre


async def scenario():
    done = await post.read(count=100)  # count filters out python's startup reads
    print(f"read: {done.data!r} (retval {done.retval})")

    call = await pre.write()
    print(f"write: {call.data!r}")
