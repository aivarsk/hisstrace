"""Track every read and write on one fd until it is closed.

    hisstrace scenario examples/trackfd.py -- python3 -c \
        "import os; f = os.open('/etc/hostname', os.O_RDONLY | os.O_NOFOLLOW); os.read(f, 100); os.close(f)"
"""

import os

from hisstrace import any_of, post, pre


async def scenario():
    # os.open adds O_CLOEXEC before the kernel sees the flags, so the filter
    # must include it; O_NOFOLLOW keeps the combination distinctive. Post
    # matchers also see failed opens, so skip those.
    while True:
        opened = await post.openat(flags=os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if opened.succeeded:
            break
    fd = opened.retval
    print(f"tracking fd {fd}")

    while True:
        event = await any_of(post.read(fd=fd), pre.write(fd=fd), pre.close(fd=fd))
        if event.name == "close":
            print("closed; done")
            break
        print(event.name, event.data)
