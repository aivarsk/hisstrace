"""Decrypt a Go SSH client's session end to end.

    hisstrace scenario examples/ssh_decrypted.py -- ./ssh-client user@192.168.8.144

Go 1.26 runs FIPS 140 mode: KEX randomness comes from an in-process DRBG, so
neither the getrandom syscall nor crypto/rand buffers reveal the session keys.
But crypto/ecdh.x25519ScalarMult receives the private scalar and the peer
public point as plain arguments, and the binary has symbols, so we plant one
int3 there (hisstrace's Trap event). At the trap the registers hand over both
values (the point equals the Q_S seen on the wire), X25519 yields the shared
secret, and the captured KEXINIT transcript plus the RFC 4253 KDF rebuild the
aes128-gcm keys; packets decrypt per RFC 5647 (length as AAD, the KDF iv's
last 8 bytes as the per-packet counter). Everything after NEWKEYS decrypts:
service request, publickey auth, the exec request, the command output.

x86-64 only (reads registers directly). Everything crypto is pure Python.
"""

import base64
import hashlib
import ipaddress
import os
import subprocess

from hisstrace import Trap, any_of, post, pre, tracer
from hisstrace import ptrace

HOST = ipaddress.ip_address("192.168.8.144")
SCALARMULT = "crypto/ecdh.x25519ScalarMult"

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

CATEGORIES = [
    "kex", "server host key",
    "cipher c2s", "cipher s2c", "mac c2s", "mac s2c",
    "compression c2s", "compression s2c", "language c2s", "language s2c",
]


# ---------------------------------------------------------------- x25519 (RFC 7748)

_P = 2**255 - 19


def x25519(k, u):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    scalar = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little")
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (scalar >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        da = (x3 - z3) * a % _P
        cb = (x3 + z3) * b % _P
        x3, z3 = (da + cb) ** 2 % _P, x1 * (da - cb) ** 2 % _P
        x2, z2 = aa * bb % _P, e * (aa + 121665 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


BASEPOINT = b"\x09" + b"\x00" * 31


# ---------------------------------------------------------------- AES-128-GCM

def _gf8_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return r


_INV = [0] * 256
for _x in range(1, 256):
    for _y in range(1, 256):
        if _gf8_mul(_x, _y) == 1:
            _INV[_x] = _y
            break

SBOX = []
for _x in range(256):
    _s = _INV[_x]
    for _i in range(1, 5):
        _s ^= ((_INV[_x] << _i) | (_INV[_x] >> (8 - _i))) & 0xFF
    SBOX.append(_s ^ 0x63)

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key):
    ks = list(key)
    for i in range(16, 176, 4):
        t = ks[i - 4:i]
        if i % 16 == 0:
            t = [SBOX[t[1]] ^ RCON[i // 16 - 1], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
        ks += [ks[i - 16 + j] ^ t[j] for j in range(4)]
    return ks


def _encrypt_block(ks, block):
    s = [block[i] ^ ks[i] for i in range(16)]
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
             s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
        if rnd < 10:
            for c in range(4):
                i = 4 * c
                a0, a1, a2, a3 = s[i:i + 4]
                s[i] = _gf8_mul(a0, 2) ^ _gf8_mul(a1, 3) ^ a2 ^ a3
                s[i + 1] = a0 ^ _gf8_mul(a1, 2) ^ _gf8_mul(a2, 3) ^ a3
                s[i + 2] = a0 ^ a1 ^ _gf8_mul(a2, 2) ^ _gf8_mul(a3, 3)
                s[i + 3] = _gf8_mul(a0, 3) ^ a1 ^ a2 ^ _gf8_mul(a3, 2)
        s = [s[i] ^ ks[16 * rnd + i] for i in range(16)]
    return bytes(s)


def _ghash_mul(x, h):
    r, v = 0, h
    for i in range(128):
        if (x >> (127 - i)) & 1:
            r ^= v
        v = (v >> 1) ^ (0xE1000000000000000000000000000000 if v & 1 else 0)
    return r


class AesGcm:
    """AES-128-GCM; aad is the 4-byte plaintext packet length (draft-agl-ssh-aes-gcm)."""

    def __init__(self, key):
        self.ks = _expand_key(key)
        self.h = int.from_bytes(_encrypt_block(self.ks, b"\0" * 16), "big")

    def _ctr(self, j0, data):
        out = bytearray()
        ctr = j0[:-4] + ((int.from_bytes(j0[-4:], "big") + 1) & 0xFFFFFFFF).to_bytes(4, "big")
        for i in range(0, len(data), 16):
            out += bytes(a ^ b for a, b in zip(data[i:i + 16], _encrypt_block(self.ks, ctr)))
            ctr = ctr[:-4] + ((int.from_bytes(ctr[-4:], "big") + 1) & 0xFFFFFFFF).to_bytes(4, "big")
        return bytes(out)

    def open(self, nonce, ct, tag, aad):
        j0 = nonce + b"\0\0\0\1"
        y = 0
        data = aad + b"\0" * (-len(aad) % 16) + ct + b"\0" * (-len(ct) % 16)
        data += (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
        for i in range(0, len(data), 16):
            y = _ghash_mul(y ^ int.from_bytes(data[i:i + 16], "big"), self.h)
        expect = y ^ int.from_bytes(_encrypt_block(self.ks, j0), "big")
        if expect != int.from_bytes(tag, "big"):
            raise ValueError("GCM tag mismatch")
        return self._ctr(j0, ct)


# ---------------------------------------------------------------- SSH wire parsing

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
    # K enters the exchange hash and the KDF as x/crypto/ssh stores it in
    # kexResult.K: a length-prefixed mpint (marshalInt writes the 4-byte
    # length, then the minimal big-endian bytes, 0x00-guarded if needed).
    return ssh_string(b"\0" + data if data[0] & 0x80 else data)


class Stream:
    """One direction: version line, then plaintext packets, up to NEWKEYS."""

    def __init__(self, label):
        self.label = label
        self.buf = bytearray()
        self.version = None
        self.kexinit = None
        self.newkeys = False
        self.packets = 0  # consumed packets; the seqnr of the next encrypted
        # one continues from here

    def feed(self, data):
        self.buf += data
        if self.version is None:
            end = self.buf.find(b"\n")
            if end < 0:
                return
            self.version = bytes(self.buf[:end]).rstrip(b"\r")
            del self.buf[:end + 1]
            print(f"{self.label} {self.version.decode('ascii', 'replace')}")
        while not self.newkeys and len(self.buf) >= 5:
            packet_length = int.from_bytes(self.buf[0:4], "big")
            if packet_length < 12 or packet_length > 65536:
                print(f"{self.label} desynced (packet_length={packet_length})")
                self.buf.clear()
                return
            if len(self.buf) < 4 + packet_length:
                return
            padding_length = self.buf[4]
            payload = bytes(self.buf[5:4 + packet_length - padding_length])
            del self.buf[:4 + packet_length]
            self.packets += 1
            self.message(payload)

    def message(self, payload):
        mtype = payload[0]
        if mtype == 20:
            c = Cursor(payload)
            c.byte()
            c.skip(16)
            self.kexinit = [c.namelist() for _ in range(10)]
            self.kexinit_payload = payload
            print(f"{self.label} message 20 KEXINIT ({len(self.kexinit[0])} kex, "
                  f"{len(self.kexinit[1])} host key, {len(self.kexinit[2])} ciphers)")
        elif mtype == 21:
            self.newkeys = True
        elif mtype == 30:
            c = Cursor(payload)
            c.byte()
            self.q_c = c.string()
        elif mtype == 31:
            c = Cursor(payload)
            c.byte()
            self.k_s = c.string()
            self.q_s = c.string()


class Decryptor:
    """Decrypts one direction after NEWKEYS: length (plaintext, aad) + GCM body + tag.

    agl's aes-gcm construction (x/crypto/ssh and OpenSSH): the whole 12-byte
    KDF iv is the nonce, and bytes 4-12 are a big-endian counter that starts
    at whatever the KDF produced and increments per packet.
    """

    def __init__(self, label, key, iv):
        self.label = label
        self.gcm = AesGcm(key)
        self.fixed = iv[:4]
        self.ctr = int.from_bytes(iv[4:12], "big")
        self.buf = bytearray()
        self.done = 0

    def feed(self, data):
        self.buf += data
        while len(self.buf) >= 4:
            packet_length = int.from_bytes(self.buf[:4], "big")
            if packet_length < 12 or packet_length > 65536:
                print(f"{self.label} lost sync (packet_length={packet_length})")
                self.buf.clear()
                return
            total = 4 + packet_length + 16
            if len(self.buf) < total:
                return
            packet = bytes(self.buf[:total])
            del self.buf[:total]
            plain = self.open(packet)
            if plain is None:
                skipped = self.resync()
                if skipped is None:
                    print(f"{self.label} unrecoverable GCM failure at packet #{self.done}", flush=True)
                    self.buf.clear()
                    return
                print(f"{self.label} resynced: skipped {skipped} stray bytes before packet #{self.done}", flush=True)
                continue
            padding_length = plain[0]
            show(self.label, plain[1:len(plain) - padding_length])

    def open(self, packet):
        plen = int.from_bytes(packet[:4], "big")
        ct, tag, aad = packet[4:4 + plen], packet[4 + plen:], packet[:4]
        nonce = self.fixed + self.ctr.to_bytes(8, "big")
        try:
            plain = self.gcm.open(nonce, ct, tag, aad)
        except ValueError:
            return None
        self.ctr += 1
        return plain

    def resync(self, limit=512):
        """A packet failed to authenticate; hunt for the next real boundary.

        Returns bytes skipped, or None when no boundary verifies. On success
        the counter points past the recovered packet, which is shown.
        """
        for skip in range(1, min(limit, len(self.buf))):
            base = self.ctr
            buf = self.buf[skip:]
            if len(buf) < 8:
                return None
            plen = int.from_bytes(buf[:4], "big")
            if plen < 12 or plen > 65536 or len(buf) < 4 + plen + 16:
                continue
            for cand in (base, base + 1):
                nonce = self.fixed + cand.to_bytes(8, "big")
                try:
                    plain = self.gcm.open(nonce, buf[4:4 + plen], buf[4 + plen:4 + plen + 16], buf[:4])
                except ValueError:
                    continue
                del self.buf[:skip + 4 + plen + 16]
                self.ctr = cand + 1
                padding_length = plain[0]
                show(self.label, plain[1:len(plain) - padding_length])
                self.done += 1
            if self.label.startswith("server"):
                print(f"  s2c pkt#{self.done} fed={self.fed} plen={packet_length}", flush=True)
                return skip
        return None


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
    elif mtype in (51,):
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
        elif kind in ("pty-req", "shell"):
            detail = ""
        print(f"{label} {name}: {kind}{detail} on channel {channel}")
    else:
        print(f"{label} {name} ({len(payload)} bytes)")


# ---------------------------------------------------------------- breakpoint glue

def symbol_addr(pid, name):
    binary = os.readlink(f"/proc/{pid}/exe")
    out = subprocess.run(["nm", binary], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == name:
            return int(parts[0], 16)
    raise ValueError(f"symbol not found in {binary}: {name}")


def shared_secret(trap, q_s):
    """x25519ScalarMult(out, scalar, point): out in rax, scalar in rdi, point in r9."""
    scalar = ptrace.peek(trap.tid, trap.regs.rdi, 32)
    point = ptrace.peek(trap.tid, trap.regs.r9, 32)
    if point == q_s:
        return x25519(scalar, point)
    return None


# ---------------------------------------------------------------- key derivation

def derive(client, server, k_shared):
    # K enters the exchange hash and the KDF as x/crypto/ssh stores it in
    # kexResult.K: a length-prefixed mpint (marshalInt writes the 4-byte
    # length, then the minimal big-endian bytes, 0x00-guarded if needed).
    k = ssh_mpint(k_shared)

    transcript = (
        ssh_string(client.version) + ssh_string(server.version)
        + ssh_string(client.kexinit_payload) + ssh_string(server.kexinit_payload)
        + ssh_string(server.k_s) + ssh_string(client.q_c) + ssh_string(server.q_s)
        + k
    )
    h = hashlib.sha256(transcript).digest()
    print(f"exchange hash H: {h.hex()}")

    def kdf(letter, n):
        return hashlib.sha256(k + h + letter + h).digest()[:n]

    keys = {
        "c2s": (kdf(b"C", 16), kdf(b"A", 12)),
        "s2c": (kdf(b"D", 16), kdf(b"B", 12)),
    }
    return keys


def connects_to(call, host):
    return call.sockaddr("addr").address == str(host)


# ---------------------------------------------------------------- scenario

async def scenario():
    t = tracer()
    addr = symbol_addr(t.pid, SCALARMULT)
    t.set_breakpoint(addr)
    print(f"breakpoint: {SCALARMULT} at {addr:#x}")

    client, server = Stream("client ->"), Stream("server ->")
    mults = []  # (scalar, point) pairs from every x25519ScalarMult trap
    fd = None
    decrypting = False

    while True:
        # match reads from the start: the server banner must not slip past
        # the connect matcher before the fd is known
        event = await any_of(pre.connect(), pre.write(fd=fd), post.read(fd=fd), post.close(fd=fd))
        if isinstance(event, Trap):
            if event.addr == addr:
                # x25519ScalarMult(out, scalar, point): scalar in rdi, point in r9
                scalar = ptrace.peek(event.tid, event.regs.rdi, 32)
                point = ptrace.peek(event.tid, event.regs.r9, 32)
                mults.append((scalar, point))
            continue
        if event.name == "connect":
            if connects_to(event, HOST):
                fd = event.args.fd
                print(f"connected to {HOST} on fd {fd}")
            continue
        if event.name == "close":
            print("connection closed")
            return
        if not event.data:
            continue

        if not decrypting:
            feed = client if event.name == "write" else server
            feed.feed(event.data)
            if client.newkeys and server.newkeys:
                match = next((m for m in mults if m[1] == server.q_s), None)
                if match is None:
                    print(f"no trap matched Q_S ({len(mults)} scalarMult traps seen)")
                    return
                secret = x25519(*match)
                print(f"shared secret recovered ({secret.hex()[:16]}...)")
                t.clear_breakpoint(addr)  # no more ECDH this session
                keys = derive(client, server, secret)
                decrypting = True
                c2s = Decryptor("client ->", *keys["c2s"])
                s2c = Decryptor("server ->", *keys["s2c"])
                c2s.feed(bytes(client.buf))  # ciphertext already received
                s2c.feed(bytes(server.buf))
        else:
            (c2s if event.name == "write" else s2c).feed(event.data)
