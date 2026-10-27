"""Watch curl talk HTTP to httpforever.com and print the conversation.

    hisstrace scenario examples/httpforever.py -- curl -s http://httpforever.com/

Finds the TCP socket on port 80 (curl opens others for DNS, and may retry
addresses), then prints every request byte leaving (->) and every response
byte arriving (<-) until the connection closes.
"""

from hisstrace import any_of, post, pre
from hisstrace import ptrace

PORT = 80


async def find_http_socket():
    while True:  # curl probes unix sockets and DNS first, and may retry addresses
        call = await pre.connect()
        raw = ptrace.peek(call.tid, call.args.addr, 4)  # sockaddr: family native, port big
        family = int.from_bytes(raw[:2], "little")
        port = int.from_bytes(raw[2:4], "big")
        if port == PORT and family in (2, 10):  # TCP or TCP6
            return call.args.fd


async def scenario():
    while True:
        fd = await find_http_socket()
        while True:
            event = await any_of(
                pre.write(fd=fd),
                pre.sendto(fd=fd),
                post.read(fd=fd),
                post.recvfrom(fd=fd),
                post.close(fd=fd),
            )
            if event.name == "close":
                break  # connection ended; curl may open the next one
            if event.data and event.name in ("write", "sendto"):
                print("->", event.data.decode(errors="replace"), end="", flush=True)
            elif event.data and event.name in ("read", "recvfrom"):
                print("<-", event.data.decode(errors="replace"), end="", flush=True)
