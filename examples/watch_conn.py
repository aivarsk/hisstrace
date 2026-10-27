"""Trace one connection round against the host in HOST: the socket's reads
and writes and every getrandom, until the connection closes.

    hisstrace scenario examples/watch_conn.py -- ./ssh-client user@192.168.8.144

The same fd serves reads and writes from several TIDs (dialer, runner, ssh
mux); that handoff is why the data lines carry the tid. Ctrl-C detaches
cleanly; a monitoring client loops forever.
"""

import ipaddress

from hisstrace import any_of, post, pre
from hisstrace import ptrace

HOST = ipaddress.ip_address("192.168.8.144")
RANDOM_CAP = 64
DATA_CAP = 48


def connects_to(call, host):
    if call.args.len < 8:  # unix sockets and DNS are someone else's business
        return False
    raw = ptrace.peek(call.tid, call.args.addr, 8)  # sockaddr_in: family, port, addr
    return int.from_bytes(raw[:2], "little") == 2 and raw[4:8] == host.packed


def show_random(done):
    if done.failed:
        print(f"getrandom(...) = errno {done.error}")
        return
    data = ptrace.peek(done.tid, done.args.buf, min(done.args.count, RANDOM_CAP))
    print(f"getrandom(count={done.args.count}, flags={done.args.flags}) = {done.retval}: {data.hex()}")


def show_data(event):
    arrow = "->" if event.name == "write" else "<-"
    data = event.data or b""
    preview = data[:DATA_CAP].hex()
    more = "..." if len(data) > DATA_CAP else ""
    print(f"[tid {event.tid}] {arrow} {event.name} {len(data)} bytes: {preview}{more}")


async def scenario():
    while True:  # the client also hits unix sockets; find the SSH one
        call = await pre.connect()
        if connects_to(call, HOST):
            break
    fd = call.args.fd
    print(f"connected to {HOST} on fd {fd}")

    while True:
        event = await any_of(
            pre.write(fd=fd),
            post.read(fd=fd),
            post.getrandom(),
            post.close(fd=fd),
        )
        if event.name == "close":
            print("connection closed; done")
            return
        if event.name == "getrandom":
            show_random(event)
        elif event.data:
            show_data(event)
