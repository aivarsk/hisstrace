"""Force Go's getrandom onto the syscall path, recover the KEX scalar, decrypt
the whole SSH session. Symbol-free, breakpoint-free, no nm anywhere.

    pip install cryptography   # scenarios may use third-party libs; hisstrace itself may not
    hisstrace scenario examples/ssh_rng_via_syscall.py -- ./ssh-client user@192.168.8.144

How it works, in three phases:

1. Patch (no symbols). Go's internal/syscall/unix.GetRandom tries the vDSO
   first and falls back to the raw getrandom syscall when runtime.vgetrandom
   reports "not handled" (bl == 0). The selector is a single `je` after
   `test %bl,%bl`; flipping it to `jmp` (74 -> eb) routes every crypto
   getrandom through the kernel syscall, where ptrace sees it. The byte is
   found by signature: the only `mov $0x13e,%eax` in the binary (getrandom =
   318), validated by the spill-reload prefix 10 bytes back and the
   call/test/je shape before it. Works on stripped binaries; refuses
   unknown builds. The patch is memory-only, takes effect from the next
   GetRandom call, and survives detach.

2. Identify the scalar (no breakpoints). Each getrandom syscall exit is
   peeked; the client's KEX_ECDH_INIT (SSH message 30, plaintext) carries
   Q_C = x25519(scalar, basepoint). The candidate whose public key matches
   Q_C is the private scalar; the server's Q_S from KEX_ECDH_REPLY (message
   31) plus the scalar gives the shared secret via X25519.

3. Decrypt everything. The captured version lines, KEXINIT payloads, host
   key, Q_C and Q_S rebuild the RFC 4253 exchange hash and KDF (K enters as
   a length-prefixed mpint, as x/crypto/ssh stores it). Packets after
   NEWKEYS decrypt per RFC 5647: plaintext length is the only AAD, and the
   whole 12-byte KDF iv is the nonce with bytes 4-12 a big-endian counter
   starting at the KDF value (agl's scheme, x/crypto incIV).

Peek accounting: 8 bytes for the connect sockaddr, getrandom exit buffers
(32 bytes for the scalar), and the scenario API's own read/write snapshots.
The only crypto implemented here is SHA-256 (hashlib); X25519 and AES-GCM
come from the `cryptography` package.
"""

import hashlib
import ipaddress

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hisstrace import any_of, post, pre, tracer
from hisstrace import ptrace

HOST = ipaddress.ip_address("192.168.8.144")

ANCHOR = b"\xb8\x3e\x01\x00\x00"          # mov $0x13e,%eax   (getrandom = 318)
SPILL_PREFIX = b"\x48\x8b\x5c\x24\x38\x48\x89\x5c\x24\x20"


def find_getrandom_fallback_je(image):
    """File offset of the je that selects the getrandom-syscall fallback, or None."""
    if image.count(ANCHOR) != 1:
        return None  # misaligned immediate or missing: not a Go-1.26-shaped build
    anchor = image.find(ANCHOR)
    if image[anchor - 0x0A:anchor] != SPILL_PREFIX:
        return None
    for je in range(anchor - 0x30, max(anchor - 0x100, 0), -1):
        if image[je] == 0x74 and image[je - 2:je] == b"\x84\xdb":
            rel8 = image[je + 1]
            target = je + 2 + (rel8 - 256 if rel8 > 127 else rel8)
            if target <= anchor - 0x0A and anchor <= target + 0x40 and image[je - 7] == 0xE8:
                return je  # the 0x74 opcode byte itself
    return None


# ------------------------------------------------------------------ SSH crypto

BASEPOINT = b"\x09" + b"\x00" * 31


def x25519_public(raw_scalar):
    key = X25519PrivateKey.from_private_bytes(raw_scalar)
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519_shared(raw_scalar, peer_public):
    key = X25519PrivateKey.from_private_bytes(raw_scalar)
    return key.exchange(X25519PublicKey.from_public_bytes(peer_public))


def ssh_string(data):
    return len(data).to_bytes(4, "big") + data


def ssh_mpint(data):
    # K enters the exchange hash and KDF as x/crypto/ssh stores it: a
    # length-prefixed mpint (marshalInt writes the length, then minimal
    # big-endian bytes, 0x00-guarded if the high bit is set).
    return ssh_string(b"\0" + data if data[0] & 0x80 else data)


def derive(client, server, k_shared):
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


class Decryptor:
    """One direction after NEWKEYS: length in the clear (AAD), then GCM body+tag."""

    def __init__(self, label, key, iv):
        self.label = label
        self.aes = AESGCM(key)
        self.fixed = iv[:4]
        self.ctr = int.from_bytes(iv[4:12], "big")
        self.buf = bytearray()

    def feed(self, data):
        self.buf += data
        while len(self.buf) >= 4:
            plen = int.from_bytes(self.buf[:4], "big")
            if plen < 12 or plen > 65536:
                print(f"{self.label} lost sync (plen={plen})")
                self.buf.clear()
                return
            total = 4 + plen + 16
            if len(self.buf) < total:
                return
            packet = bytes(self.buf[:total])
            del self.buf[:total]
            nonce = self.fixed + self.ctr.to_bytes(8, "big")
            try:
                plain = self.aes.decrypt(nonce, packet[4:], packet[:4])
            except Exception:
                print(f"{self.label} GCM failure at packet #{self.ctr}")
                self.buf.clear()
                return
            self.ctr += 1
            padding = plain[0]
            show(self.label, plain[1:len(plain) - padding])


# ------------------------------------------------------------- SSH wire parsing

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
        v = self.data[self.i]
        self.i += 1
        return v

    def skip(self, n):
        self.i += n

    def uint32(self):
        v = int.from_bytes(self.data[self.i:self.i + 4], "big")
        self.i += 4
        return v

    def string(self):
        n = self.uint32()
        v = bytes(self.data[self.i:self.i + n])
        self.i += n
        return v


class Stream:
    """One direction up to NEWKEYS: version line, then plaintext packets;
    whatever arrives after NEWKEYS stays buffered as ciphertext."""

    def __init__(self, label):
        self.label = label
        self.buf = bytearray()
        self.version = None
        self.kexinit = None
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
            if length < 12 or len(self.buf) < 4 + length:
                return
            payload = bytes(self.buf[5:4 + length - self.buf[4]])
            del self.buf[:4 + length]
            self.message(payload)

    def message(self, payload):
        mtype = payload[0]
        if mtype == 20:
            self.kexinit = payload
            print(f"{self.label} message 20 KEXINIT")
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


# ------------------------------------------------------------------- scenario

async def scenario():
    t = tracer()
    # phase 1: find and flip the fallback selector (no symbols)
    image = t.exe_image()
    patch_off = find_getrandom_fallback_je(image)
    if patch_off is None:
        print("getrandom fallback selector not found; refusing to patch this build")
        return
    vaddr = t.exe_vaddr(patch_off)
    cur = ptrace.peek(t.pid, vaddr, 1)
    if cur != b"\x74":
        print(f"unexpected byte at {vaddr:#x}: {cur.hex()}, refusing to patch")
        return
    ptrace.poke(t.pid, vaddr, b"\xeb")
    print(f"patched getrandom fallback selector at {vaddr:#x}: je -> jmp (1 byte)")

    # phase 2 + 3: capture and decrypt
    client, server = Stream("client ->"), Stream("server ->")
    reads = []        # (seq, bytes) from getrandom exits
    decrypting = False
    fd = None
    seq = 0
    while True:
        event = await any_of(pre.connect(), pre.write(fd=fd), post.read(fd=fd),
                             post.close(fd=fd), post.getrandom())
        seq += 1
        if event.name == "getrandom":
            if event.succeeded and 0 < event.retval <= 512:
                reads.append((seq, ptrace.peek(event.tid, event.args.buf, event.retval)))
            continue
        if event.name == "connect":
            if event.sockaddr("addr").address == str(HOST):
                    fd = event.args.fd
                    print(f"connected to {HOST} on fd {fd}")
            continue
        if event.name == "close":
            print("connection closed")
            break
        if not event.data:
            continue
        if event.name == "write":
            client.feed(event.data)
        else:
            server.feed(event.data)
        if (not decrypting and client.newkeys and server.newkeys
                and client.q_c and server.q_s):
            scalar = next((d for _, d in reads
                           if len(d) == 32 and x25519_public(d) == client.q_c), None)
            if scalar is None:
                print("scalar not found among getrandom buffers; cannot decrypt")
                return
            print(f"KEX private scalar: {scalar.hex()}")
            keys = derive(client, server, x25519_shared(scalar, server.q_s))
            decrypting = True
            c2s = Decryptor("client ->", *keys["c2s"])
            s2c = Decryptor("server ->", *keys["s2c"])
            c2s.feed(bytes(client.buf))
            s2c.feed(bytes(server.buf))
        elif decrypting:
            (c2s if event.name == "write" else s2c).feed(event.data)

    sizes = {}
    for _, d in reads:
        sizes[len(d)] = sizes.get(len(d), 0) + 1
    print(f"getrandom syscalls: {len(reads)}, sizes: {dict(sorted(sizes.items()))}")
