"""Decrypt a Go SSH client's session end to end.

    hisstrace scenario examples/ssh_decrypted.py -- ./ssh-client user@192.168.8.144

The client keeps its X25519 private key in memory, and the binary has
symbols: one breakpoint on crypto/ecdh.x25519ScalarMult (hisstrace's Trap
event) hands over scalar and peer point in the trap registers. Matching the
point against the wire Q_S identifies the real KEX call among the decoy
self-test traps; X25519 yields the shared secret, and the captured KEXINIT
transcript plus the RFC 4253 KDF rebuild the aes128-gcm keys. Packets
decrypt per RFC 5647 (length as AAD, the whole 12-byte KDF iv as the nonce,
bytes 4-12 a big-endian counter starting at the KDF value). Everything
after NEWKEYS decrypts: service request, publickey auth, the exec request,
the command output.

Wire parsing and key derivation live in examples/_ssh.py, shared with the
other SSH scenarios. x86-64 only (reads registers directly); the AES-GCM
here is pure Python.
"""

from hisstrace import Trap, any_of, post, pre, tracer
from hisstrace import ptrace

from _ssh import HOST, Stream, connects_to, derive, show, symbol_addr

SCALARMULT = "crypto/ecdh.x25519ScalarMult"


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


class Decryptor:
    """One direction after NEWKEYS: length (plaintext, aad) + GCM body + tag."""

    def __init__(self, label, key, iv):
        self.label = label
        self.gcm = AesGcm(key)
        self.fixed = iv[:4]
        self.ctr = int.from_bytes(iv[4:12], "big")
        self.buf = bytearray()

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
            nonce = self.fixed + self.ctr.to_bytes(8, "big")
            try:
                plain = self.gcm.open(nonce, packet[4:4 + packet_length], packet[4 + packet_length:], packet[:4])
            except ValueError:
                print(f"{self.label} GCM failure at packet #{self.ctr}")
                self.buf.clear()
                return
            self.ctr += 1
            padding_length = plain[0]
            show(self.label, plain[1:len(plain) - padding_length])


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
            if connects_to(event):
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
