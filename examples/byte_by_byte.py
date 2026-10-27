"""httpforever.py, except every socket read and write is shrunk to 1 byte.

    hisstrace scenario examples/byte_by_byte.py -- wget -q -O /dev/null http://httpforever.com/

At a pre-match the tracee is stopped at syscall entry, so the scenario can
rewrite the request before the kernel sees it: the count-style calls
(read/write/recvfrom/sendto) get call.overwrite (names come from the syscall
table: count for read/write, len for recvfrom/sendto), and the iovec-style
calls get a single poke: recvmsg/sendmsg keep 1 byte by forcing msg_iovlen to
1 and iov[0].iov_len to 1, readv/writev the same through vlen/iov_len. The
kernel then moves the whole conversation one byte per syscall, and the
post-matches reassemble both streams.

Tracking, not just matching: curl opens several port-80 connections (happy
eyeballs over IPv4 and IPv6) and keeps only one, may fork the transfer into a
child, and fds get reused. So the scenario watches every socket io syscall
unfiltered, keeps a set of live (pid, fd) connections (added on a port-80
connect, removed on close), and only clamps calls whose connection it knows.

wget is the documented client because it reads sequentially. curl also works,
but its nonblocking reader thread spins recvfrom-EAGAIN on the connection fd
while waiting, and every spin is a matched call that gets clamped and
awaited, so the transfer crawls at dozens of bytes per second. MSG_PEEK calls
(recvfrom/recvmsg with flags & 2, which wget uses to parse chunked responses)
are left untouched: they re-deliver bytes without consuming them, and
clamping them would break the chunk parsing they exist for.
"""

from hisstrace import Child, any_of, on, post, pre
from hisstrace import ptrace

INCOMING = ("read", "recvfrom", "recvmsg", "readv")
SIZE_ARG = {"read": "count", "write": "count", "recvfrom": "len", "sendto": "len"}
ONE = (1).to_bytes(8, "little")
NAMES = (*INCOMING, "write", "sendto", "sendmsg", "writev")


def word(tid, addr):
    return int.from_bytes(ptrace.peek(tid, addr, 8), "little")


async def scenario():
    live = {}  # (pid, fd) of every port-80 connection still open
    incoming, outgoing = bytearray(), bytearray()
    io = [getattr(pre, name)() for name in NAMES]
    while True:
        event = await any_of(pre.connect(), pre.exit_group(), on.fork(), post.close(), *io)
        if isinstance(event, Child):  # the transfer may live in a forked child
            event.follow()
            continue
        if event.name == "exit_group":
            break
        if event.name == "connect":
            raw = ptrace.peek(event.tid, event.args.addr, 8)  # port is big-endian at bytes 2-4
            if int.from_bytes(raw[2:4], "big") == 80:
                live[(event.pid, event.args.fd)] = True
                print(f"connected on pid {event.pid} fd {event.args.fd}; "
                      f"forcing every read and write to 1 byte", flush=True)
            continue
        if event.name == "close":
            live.pop((event.pid, event.args.raw[0]), None)  # eyeballs losers, reuse
            continue
        key = (event.pid, event.args.raw[0])  # an io syscall; fd is arg 0 everywhere
        if key not in live:  # library reads, other sockets, other processes
            continue
        if event.name in ("recvfrom", "recvmsg") and event.args.flags & 2:
            continue  # MSG_PEEK re-delivers bytes; only the consuming read counts

        call = event
        if call.name in ("recvmsg", "sendmsg"):
            iov = word(call.tid, word(call.tid, call.args.msg + 16))  # msghdr.msg_iov -> iov_base
            ptrace.poke(call.tid, iov + 8, ONE)  # iov[0].iov_len
            ptrace.poke(call.tid, call.args.msg + 24, ONE)  # msg_iovlen
        elif call.name in ("readv", "writev"):
            call.overwrite(vlen=1)
            ptrace.poke(call.tid, call.args.vec + 8, ONE)  # iov[0].iov_len
        else:
            call.overwrite(**{SIZE_ARG[call.name]: 1})

        done = await getattr(post, call.name)()
        while (done.pid, done.args.raw[0]) != key:  # someone else's io
            done = await getattr(post, call.name)()
        if not done.succeeded or not done.retval:
            continue
        if done.name in INCOMING[:2] or done.name in ("write", "sendto"):
            data = done.data or b""  # these four are snapshotted by the API
        else:  # msg/iovec calls: follow the (rewritten) descriptor chain
            if done.name in ("recvmsg", "sendmsg"):
                base = word(done.tid, word(done.tid, done.args.msg + 16))
            else:
                base = word(done.tid, done.args.vec)
            data = ptrace.peek(done.tid, base, done.retval)
        if not data:
            continue
        if done.name in INCOMING:
            incoming += data
        else:
            outgoing += data
        total = len(incoming) + len(outgoing)
        arrow = "<-" if done.name in INCOMING else "->"
        print(f"{arrow} 1 byte (total {total})", flush=True)

    print(f"\nrequest, {len(outgoing)} bytes, one syscall per byte:")
    print(outgoing.decode("utf-8", "replace"))
    print(f"response, {len(incoming)} bytes, one syscall per byte:")
    print(incoming.decode("utf-8", "replace"))
