"""
Merkle Tree Ladder (MTL) mode -- ML-DSA-44-MTL-SHAKE-128.

Implements draft-harvey-cfrg-mtl-mode-09 (Verisign Labs):
  * n = 16 (security parameter, bytes), SID = 2n = 32 bytes
  * ADRS(L,R) = L (8 bytes BE) || R (8 bytes BE), 0-based indices
  * H_leaf(SID, ADRS, Rand, ctx, msg) = cSHAKE128(SID||ADRS||Rand||OLEN(ctx)||ctx||msg, 8n, "", OID_MTL)
  * H_int (SID, ADRS, HL, HR)         = cSHAKE128(SID||ADRS||HL||HR,                    8n, "", OID_MTL)
  * binary rung strategy, backward-compatible authentication paths
  * wire formats of Sections 7.1-7.3, 9.1-9.3
The ladder is signed with ML-DSA-44 (FIPS 204, liboqs) using OID_MTL as context string.

Algorithm numbers in comments refer to the draft.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

from Crypto.Hash import cSHAKE128

N_BYTES = 16                      # security parameter n
SID_LEN = 2 * N_BYTES             # series identifier length
# The draft leaves OID_MTL abstract. Lab value; change in ONE place if the draft pins it.
OID_MTL = b"MTL-MODE:ML-DSA-44-MTL-SHAKE-128"

MTL_TYPE_CONDENSED = 0            # draft-fregly-dnsop-slh-dsa-mtl-dnssec Sec. 4
MTL_TYPE_FULL = 1

HASH_COUNTER = {"leaf": 0, "int": 0}   # instrumentation for the benchmark


# ---------------------------------------------------------------- helpers (Sec 2.3)
def lsb(x: int) -> int:
    return (x & -x).bit_length() if x else 0


def msb(x: int) -> int:
    return x.bit_length()


def bit_width(x: int) -> int:        # popcount, as named in the draft
    return bin(x).count("1")


def adrs(left: int, right: int) -> bytes:
    return struct.pack(">QQ", left, right)


def _cshake(data: bytes) -> bytes:
    return cSHAKE128.new(data=data, custom=OID_MTL).read(N_BYTES)


def H_leaf(sid: bytes, left: int, right: int, rand: bytes, ctx: bytes, msg: bytes) -> bytes:
    HASH_COUNTER["leaf"] += 1
    return _cshake(sid + adrs(left, right) + rand + bytes([len(ctx)]) + ctx + msg)


def H_int(sid: bytes, left: int, right: int, hl: bytes, hr: bytes) -> bytes:
    HASH_COUNTER["int"] += 1
    return _cshake(sid + adrs(left, right) + hl + hr)


# Algorithm 1 / 2
def hash_leaf(sid, leaf_index, randomizer, message, ctx_msg=b""):
    return H_leaf(sid, leaf_index, leaf_index, randomizer, ctx_msg, message)


def hash_int(sid, left, right, lh, rh):
    return H_int(sid, left, right, lh, rh)


# ---------------------------------------------------------------- data structures (Sec 7)
@dataclass
class Rung:
    left: int
    right: int
    hash: bytes

    def to_bytes(self) -> bytes:
        return struct.pack(">QQ", self.left, self.right) + self.hash


@dataclass
class Ladder:
    sid: bytes
    rungs: list
    flags: int = 0

    def to_bytes(self) -> bytes:
        return (struct.pack(">H", self.flags) + self.sid + struct.pack(">H", len(self.rungs))
                + b"".join(r.to_bytes() for r in self.rungs))

    @classmethod
    def from_bytes(cls, b: bytes, off: int = 0):
        flags, = struct.unpack_from(">H", b, off); off += 2
        sid = b[off:off + SID_LEN]; off += SID_LEN
        cnt, = struct.unpack_from(">H", b, off); off += 2
        rungs = []
        for _ in range(cnt):
            l, r = struct.unpack_from(">QQ", b, off); off += 16
            rungs.append(Rung(l, r, b[off:off + N_BYTES])); off += N_BYTES
        return cls(sid, rungs, flags), off

    def covers(self) -> int:
        return max((r.right for r in self.rungs), default=-1) + 1


@dataclass
class AuthPath:
    randomizer: bytes
    leaf_index: int
    rung_left: int
    rung_right: int
    sibling_hashes: list = field(default_factory=list)
    flags: int = 0

    def to_bytes(self) -> bytes:
        return (struct.pack(">H", self.flags) + self.randomizer
                + struct.pack(">QQQH", self.leaf_index, self.rung_left, self.rung_right,
                              len(self.sibling_hashes))
                + b"".join(self.sibling_hashes))

    @classmethod
    def from_bytes(cls, b: bytes, off: int = 0):
        flags, = struct.unpack_from(">H", b, off); off += 2
        rand = b[off:off + N_BYTES]; off += N_BYTES
        leaf, rl, rr, cnt = struct.unpack_from(">QQQH", b, off); off += 26
        sib = [b[off + i * N_BYTES: off + (i + 1) * N_BYTES] for i in range(cnt)]
        off += cnt * N_BYTES
        return cls(rand, leaf, rl, rr, sib, flags), off


@dataclass
class SignedLadder:
    ladder: Ladder
    signature: bytes

    def to_bytes(self) -> bytes:
        return self.ladder.to_bytes() + struct.pack(">I", len(self.signature)) + self.signature

    @classmethod
    def from_bytes(cls, b: bytes, off: int = 0):
        lad, off = Ladder.from_bytes(b, off)
        ln, = struct.unpack_from(">I", b, off); off += 4
        return cls(lad, b[off:off + ln]), off + ln


def encode_condensed(sid: bytes, ap: AuthPath) -> bytes:           # Sec 9.2
    return sid + ap.to_bytes()


def encode_full(sid: bytes, ap: AuthPath, sl: SignedLadder) -> bytes:  # Sec 9.1
    return sid + ap.to_bytes() + sl.to_bytes()


def decode_signature(b: bytes, full: bool):
    sid = b[:SID_LEN]
    ap, off = AuthPath.from_bytes(b, SID_LEN)
    sl = None
    if full:
        sl, off = SignedLadder.from_bytes(b, off)
    if off != len(b):
        raise ValueError("trailing bytes in MTL signature")
    return sid, ap, sl


# ---------------------------------------------------------------- node set (Sec 8)
class MTLNS:
    """MTL node set object. hashes keyed by (L,R); randomizers by leaf index."""

    def __init__(self, sid: bytes):
        assert len(sid) == SID_LEN
        self.sid = sid
        self.count = 0
        self.hashes: dict = {}
        self.randomizers: dict = {}

    # Algorithm 4 (mtl_append)
    def append(self, msg: bytes, ctx_msg: bytes = b"", rand: bytes | None = None) -> int:
        leaf_index = self.count
        self.count = leaf_index + 1
        rand = rand if rand is not None else os.urandom(N_BYTES)
        self.randomizers[leaf_index] = rand
        self.hashes[(leaf_index, leaf_index)] = hash_leaf(self.sid, leaf_index, rand, msg, ctx_msg)
        for i in range(1, lsb(leaf_index + 1)):
            left = leaf_index - 2 ** i + 1
            mid = leaf_index - 2 ** (i - 1) + 1
            self.hashes[(left, leaf_index)] = hash_int(
                self.sid, left, leaf_index,
                self.hashes[(left, mid - 1)], self.hashes[(mid, leaf_index)])
        return leaf_index

    # Algorithm 5 (mtl_authpath)
    def authpath(self, leaf_index: int) -> AuthPath:
        if leaf_index < 0 or leaf_index >= self.count:
            raise IndexError("leaf outside node set")
        left = 0
        right = -1
        for i in range(msb(self.count), -1, -1):
            if self.count & (1 << i):
                right = left + 2 ** i - 1
                if leaf_index <= right:
                    break
                left = right + 1
        sib = []
        for i in range(0, bit_width(right - left)):
            if leaf_index & (1 << i):
                sl = (~(2 ** i - 1) & leaf_index) - 2 ** i
            else:
                sl = (~(2 ** i - 1) & leaf_index) + 2 ** i
            sib.append(self.hashes[(sl, sl + 2 ** i - 1)])
        return AuthPath(self.randomizers[leaf_index], leaf_index, left, right, sib)

    # Algorithm 6 (mtl_ladder)
    def ladder(self) -> Ladder:
        left = 0
        rungs = []
        for i in range(msb(self.count), -1, -1):
            if self.count & (1 << i):
                right = left + 2 ** i - 1
                rungs.append(Rung(left, right, self.hashes[(left, right)]))
                left = right + 1
        return Ladder(self.sid, rungs)

    # persistence (the signer is stateful -- state must never be reset/reused)
    def to_json(self) -> dict:
        return {"sid": self.sid.hex(), "count": self.count,
                "hashes": {f"{l}:{r}": h.hex() for (l, r), h in self.hashes.items()},
                "randomizers": {str(k): v.hex() for k, v in self.randomizers.items()}}

    @classmethod
    def from_json(cls, d: dict) -> "MTLNS":
        ns = cls(bytes.fromhex(d["sid"]))
        ns.count = d["count"]
        for k, v in d["hashes"].items():
            l, r = k.split(":")
            ns.hashes[(int(l), int(r))] = bytes.fromhex(v)
        ns.randomizers = {int(k): bytes.fromhex(v) for k, v in d["randomizers"].items()}
        return ns


# Algorithm 7 (mtl_rung)
def mtl_rung(sid: bytes, ap: AuthPath, ladder: Ladder):
    if sid != ladder.sid:
        return None
    cnt = len(ap.sibling_hashes)
    left = ap.leaf_index & ~(2 ** cnt - 1)
    right = left + (2 ** cnt - 1)
    if ap.rung_left != left or ap.rung_right != right:
        return None
    best, best_deg = None, -1
    for r in ladder.rungs:
        if r.left <= ap.leaf_index <= r.right:
            deg = lsb(r.right - r.left + 1) - 1
            if (((deg <= lsb(r.left) - 1) or lsb(r.left) == 0)
                    and (r.right - r.left + 1 == 2 ** deg) and deg <= cnt):
                if best is None or deg < best_deg:
                    best, best_deg = r, deg
    return best


# Algorithm 8 (mtl_verify)
def mtl_verify(sid: bytes, msg: bytes, ap: AuthPath, rung: Rung, ctx_msg: bytes = b"") -> bool:
    leaf = ap.leaf_index
    target = hash_leaf(sid, leaf, ap.randomizer, msg, ctx_msg)
    if leaf == rung.left and leaf == rung.right:
        return target == rung.hash
    for i in range(1, len(ap.sibling_hashes) + 1):
        left = leaf & ~(2 ** i - 1)
        right = left + 2 ** i - 1
        mid = left + 2 ** (i - 1)
        s = ap.sibling_hashes[i - 1]
        target = hash_int(sid, left, right, target, s) if leaf < mid else hash_int(sid, left, right, s, target)
        if left == rung.left and right == rung.right:
            return target == rung.hash
    return False
