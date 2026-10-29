"""Shared helpers for the SSH examples: wire parsing, message display, and
the bits every scenario needs (symbol lookup, connect matching). Imported by
ssh_decrypted.py, ssh_rng_via_syscall.py, ssh_handshake.py, and
ssh_drbg_replay.py; not a scenario itself. scenario.load() puts this
directory on sys.path, so examples share one copy instead of four.
"""

import hashlib
import ipaddress
import os
import subprocess

HOST = ipaddress.ip_address("192.168.8.144")

BASEPOINT = b"\x09" + b"\x00" * 31

CATEGORIES = [
    "kex", "server host key",
    "cipher c2s", "cipher s2c", "mac c2s", "mac s2c",
    "compression c2s", "compression s2c", "language c2s", "language s2c",
]

MSG_NAMES = {
    1: "DISCONNECT", 2: "IGNORE", 3: "UNIMPLEMENTED", 4: "DEBUG",
    5: "SERVICE_REQUEST", 6: "SERVICE_ACCEPT", 7: "EXT_INFO",
    20: "KEXINIT", 21: "NEWKEYS",
    30: "KEX_ECDH_INIT", 31: "KEX_ECDH_REPLY",
    50: "USERAUTH_REQUEST", 51: "USERAUTH_FAILURE", 52: "USERAUTH_SUCCESS",
    90: "CHANNEL_OPEN", 91: "CHANNEL_OPEN_CONFIRMATION", 92: "CHANNEL_OPEN_FAILURE",
    93: "CHANNEL_WINDOW_ADJUST", 94: "CHANNEL_DATA", 95: "CHANNEL_EXTENDED_DATA",
    96: "CHANNEL_EOF", 97: "CHANNEL_CLOSE", 98: "CHANNEL_REQUEST",
    99: "CHANNEL_SUCCESS", 100: "CHANNEL_FAILURE",
}


class Cursor:
    def __init__(self, data):
        self.data = data
        self.i = 0

    def byte(self):
        value = self.data[self.i]
        self.i += 1
        return value

    def skip(self, n):
        self.i += n

    def uint32(self):
        value = int.from_bytes(self.data[self.i:self.i + 4], "big")
        self.i += 4
        return value

    def string(self):
        n = self.uint32()
        value = bytes(self.data[self.i:self.i + n])
        self.i += n
        return value

    def namelist(self):
        text = self.string().decode("ascii", "replace")
        return [name for name in text.split(",") if name]


def ssh_string(data):
    return len(data).to_bytes(4, "big") + data


def ssh_mpint(data):
    # K enters the exchange hash and KDF as x/crypto/ssh stores it: a
    # length-prefixed mpint (marshalInt writes the length, then the minimal
    # big-endian bytes, 0x00-guarded if the high bit is set).
    return ssh_string(b"\0" + data if data[0] & 0x80 else data)


def show(label, payload):
    mtype = payload[0]
    name = MSG_NAMES.get(mtype, "UNKNOWN")
    c = Cursor(payload)
    c.byte()
    if mtype in (5, 6):
        print(f"{label} {name}: {c.string().decode()}")
    elif mtype == 7:
        pairs = []
        for _ in range(c.uint32()):
            ext = c.string().decode()
            pairs.append(f"{ext}={c.string().decode(errors='replace')[:40]}")
        print(f"{label} {name}: {', '.join(pairs)}")
    elif mtype == 50:
        user = c.string().decode()
        service = c.string().decode()
        method = c.string().decode()
        print(f"{label} {name}: user={user} service={service} method={method}")
    elif mtype == 51:
        print(f"{label} {name}: methods={c.string().decode()} partial={c.byte()}")
    elif mtype == 90:
        kind = c.string().decode()
        c.uint32()
        c.uint32()
        print(f"{label} {name}: {kind}")
    elif mtype in (91, 92):
        print(f"{label} {name}: channel={c.uint32()}")
    elif mtype == 94:
        channel = c.uint32()
        data = c.string()
        print(f"{label} {name} on channel {channel}: {data.decode('utf-8', 'replace')}")
    elif mtype == 98:
        channel = c.uint32()
        kind = c.string().decode()
        detail = ""
        if kind == "exec":
            c.byte()
            detail = f" command={c.string().decode()!r}"
        print(f"{label} {name}: {kind}{detail} on channel {channel}")
    else:
        print(f"{label} {name} ({len(payload)} bytes)")


class Stream:
    """One direction up to NEWKEYS: version line, then plaintext packets;
    whatever arrives after NEWKEYS stays buffered as ciphertext."""

    def __init__(self, label):
        self.label = label
        self.buf = bytearray()
        self.version = None
        self.kexinit = None         # raw KEXINIT payload (for the transcript)
        self.kexinit_lists = None   # the ten namelists (for display/negotiation)
        self.newkeys = False
        self.q_c = self.q_s = self.host_key = None

    def feed(self, data):
        self.buf += data
        if self.version is None:
            nl = self.buf.find(b"\n")
            if nl < 0:
                return
            self.version = bytes(self.buf[:nl]).rstrip(b"\r")
            print(f"{self.label} {self.version.decode('ascii', 'replace')}")
            del self.buf[:nl + 1]
        while not self.newkeys and len(self.buf) >= 5:
            length = int.from_bytes(self.buf[0:4], "big")
            if length < 12 or length > 65536:
                print(f"{self.label} desynced (packet_length={length})")
                self.buf.clear()
                return
            if len(self.buf) < 4 + length:
                return
            padding_length = self.buf[4]
            payload = bytes(self.buf[5:4 + length - padding_length])
            del self.buf[:4 + length]
            self.message(payload)

    def message(self, payload):
        mtype = payload[0]
        if mtype == 20:
            c = Cursor(payload)
            c.byte()
            c.skip(16)  # cookie
            self.kexinit_lists = [c.namelist() for _ in range(10)]
            self.kexinit = payload
            print(f"{self.label} message 20 KEXINIT ({len(self.kexinit_lists[0])} kex, "
                  f"{len(self.kexinit_lists[1])} host key, {len(self.kexinit_lists[2])} ciphers)")
        elif mtype == 21:
            self.newkeys = True
        elif mtype == 30:
            c = Cursor(payload)
            c.byte()
            self.q_c = c.string()
        elif mtype == 31:
            c = Cursor(payload)
            c.byte()
            self.host_key = c.string()
            self.q_s = c.string()


def derive(client, server, k_shared):
    """RFC 4253 exchange hash and KDF from the captured handshake. Prints H."""
    transcript = (
        ssh_string(client.version) + ssh_string(server.version)
        + ssh_string(client.kexinit) + ssh_string(server.kexinit)
        + ssh_string(server.host_key) + ssh_string(client.q_c) + ssh_string(server.q_s)
        + ssh_mpint(k_shared)
    )
    h = hashlib.sha256(transcript).digest()
    print(f"exchange hash H: {h.hex()}")

    def kdf(letter, n):
        return hashlib.sha256(ssh_mpint(k_shared) + h + letter + h).digest()[:n]

    return {"c2s": (kdf(b"C", 16), kdf(b"A", 12)), "s2c": (kdf(b"D", 16), kdf(b"B", 12))}


def symbol_addr(pid, name):
    binary = os.readlink(f"/proc/{pid}/exe")
    out = subprocess.run(["nm", binary], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == name:
            return int(parts[0], 16)
    raise ValueError(f"symbol not found in {binary}: {name}")


def connects_to(call, host=HOST):
    return call.sockaddr("addr").address == str(host)
