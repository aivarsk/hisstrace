"""Audit every socket an application opens: is it non-blocking?

    hisstrace scenario examples/socket_audit.py -- python3 yourapp.py

The classic event-loop stall: an asyncio or threaded app builds a TCP socket
through some sync helper, nobody calls setblocking(False), and one slow peer
freezes everything. At the syscall layer the story is plain. This scenario
tracks socket creation (socket/accept4/socketpair), the two ways a fd
commonly becomes non-blocking afterwards (fcntl(F_SETFL, O_NONBLOCK), which
is what Python's socket.setblocking and os.set_blocking emit, and
ioctl(FIONBIO)), and reports a verdict at close time: a socket that is still
blocking when it is closed gets called out, as does any socket still open
when the process exits.

Caveats: dup2/dup copy the flag state to a new fd number that this audit
does not link back to the original, and files opened on a socket path are
not sockets. TCP is the usual offender; unix sockets are audited too.
"""

from hisstrace import any_of, post, pre
from hisstrace import ptrace

O_NONBLOCK = 0o4000  # Linux: same value as a file-status flag and SOCK_NONBLOCK
F_SETFL = 4
FIONBIO = 0x5421


async def scenario():
    created = {}  # fd -> how it was made, for the close-time verdict
    nonblocking = set()  # fds observed to carry O_NONBLOCK
    peer = {}  # fd -> "ip:port" the socket connected to

    def verdict(fd):
        return "non-blocking" if fd in nonblocking else "BLOCKING"

    while True:
        done = await any_of(
            post.socket(), post.accept4(), post.socketpair(),
            post.fcntl(), post.ioctl(), post.close(), post.connect(), pre.exit_group(),
        )
        raw = done.args.raw
        if done.name == "exit_group":
            for fd in sorted(created):
                where = f" to {peer[fd]}" if fd in peer else ""
                print(f"WARNING: socket fd {fd} ({created[fd]}){where} still open and "
                      f"{verdict(fd)} at exit")
            return
        if done.name in ("socket", "accept4", "socketpair") and done.succeeded:
            if done.name == "socket":
                nonblocking.discard(done.retval)  # a fresh fd defines its own state
                created[done.retval] = f"socket(domain={raw[0]})"
                if raw[1] & O_NONBLOCK:
                    nonblocking.add(done.retval)
            elif done.name == "accept4":
                nonblocking.discard(done.retval)
                created[done.retval] = "accept4"
                if raw[3] & O_NONBLOCK:
                    nonblocking.add(done.retval)
            else:  # socketpair: both fds come back through a pointer argument
                pair = ptrace.peek(done.tid, raw[3], 8)
                fd1 = int.from_bytes(pair[:4], "little")
                fd2 = int.from_bytes(pair[4:], "little")
                made = f"socketpair(domain={raw[0]})"
                nonblocking.difference_update((fd1, fd2))
                created[fd1] = made
                created[fd2] = made
                if raw[1] & O_NONBLOCK:
                    nonblocking.update((fd1, fd2))
        elif done.name == "connect" and done.succeeded:
            # EINPROGRESS/EALREADY/EAGAIN mean the connect did not block: proof
            if done.error in (114, 115, 11):  # EALREADY, EINPROGRESS, EWOULDBLOCK
                nonblocking.add(raw[0])
            else:
                addr = ptrace.peek(done.tid, raw[1], 8)
                port = int.from_bytes(addr[2:4], "big")
                if int.from_bytes(addr[:2], "little") == 2:
                    peer[raw[0]] = ".".join(str(b) for b in addr[4:8]) + f":{port}"
                else:
                    peer[raw[0]] = f"[v6]:{port}"
        elif done.name == "fcntl" and done.succeeded and raw[1] == F_SETFL and raw[2] & O_NONBLOCK:
            nonblocking.add(raw[0])
        elif done.name == "ioctl" and raw[1] == FIONBIO and done.succeeded:
            enabled = ptrace.peek(done.tid, raw[2], 4)  # FIONBIO arg is an int*
            if enabled and int.from_bytes(enabled, "little"):
                nonblocking.add(raw[0])
        elif done.name == "close":
            fd = raw[0]
            if fd in created:
                state = verdict(fd)
                where = f" to {peer[fd]}" if fd in peer else ""
                print(f"close(fd={fd}) <- {created.pop(fd)}{where}: {state}")
                if fd not in nonblocking:
                    print(f"WARNING: socket fd {fd}{where} was closed while BLOCKING")
                nonblocking.discard(fd)
                peer.pop(fd, None)
