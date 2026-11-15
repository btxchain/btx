#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RCADMIT tickets for functional tests.

Pure-Python port of Poseidon2-Goldilocks-GL12 (t=12, rate 8, 8 full and 22
partial rounds, x^7) from src/matmul/matmul_v4_rc_alg_hash.cpp and of
RCAdmissionTicketHash / DeriveRCAdmissionTarget from
src/node/matmul_rc_admission.cpp. Slow, but a regtest ticket needs about 2^12
hashes.
"""

import hashlib
import struct

from .messages import ser_uint256, uint256_from_compact

P = 0xFFFFFFFF00000001
T, RATE, FULL, PARTIAL = 12, 8, 8, 22
DOMAIN = b"BTX_ALGHASH_P2_GL12_V1"

ADMISSION_DOMAIN = b"BTX_RC_ADMIT_P2_V1"
ADMISSION_NBITS_DISCOUNT = 48
ADMISSION_MIN_WORK_BITS = 12
ADMISSION_MAX_WORK_BITS = 20


def _sample(tag, pred=lambda v: True):
    ctr = 0
    while True:
        h = hashlib.sha256(hashlib.sha256(tag + struct.pack("<I", ctr)).digest()).digest()
        w = int.from_bytes(h[:8], "little")
        if w < P and pred(w):
            return w
        ctr += 1


def _tag(label, *ints):
    return DOMAIN + label + b"".join(struct.pack("<I", i) for i in ints)


RC_EXT = [[_sample(_tag(b"RCE", r, i)) for i in range(T)] for r in range(FULL)]
RC_INT = [_sample(_tag(b"RCI", r)) for r in range(PARTIAL)]
MU = [_sample(_tag(b"MU", i), lambda v: v != 0 and v != P - 1) for i in range(T)]


def _m4(b):
    t0 = (b[0] + b[1]) % P
    t1 = (b[2] + b[3]) % P
    t2 = (2 * b[1] + t1) % P
    t3 = (2 * b[3] + t0) % P
    t4 = (4 * t1 + t3) % P
    t5 = (4 * t0 + t2) % P
    return [(t3 + t5) % P, t5, (t2 + t4) % P, t4]


def _external(s):
    s = _m4(s[0:4]) + _m4(s[4:8]) + _m4(s[8:12])
    for k in range(4):
        tot = (s[k] + s[4 + k] + s[8 + k]) % P
        for b in range(3):
            s[4 * b + k] = (s[4 * b + k] + tot) % P
    return s


def _internal(s):
    tot = sum(s) % P
    return [(tot + MU[i] * s[i]) % P for i in range(T)]


def permute(s):
    s = _external(list(s))
    for r in range(FULL // 2):
        s = _external([pow((s[i] + RC_EXT[r][i]) % P, 7, P) for i in range(T)])
    for r in range(PARTIAL):
        s[0] = pow((s[0] + RC_INT[r]) % P, 7, P)
        s = _internal(s)
    for r in range(FULL // 2):
        s = _external([pow((s[i] + RC_EXT[FULL // 2 + r][i]) % P, 7, P) for i in range(T)])
    return s


def sponge_hash(xs):
    padded = [x % P for x in xs] + [1]
    while len(padded) % RATE:
        padded.append(0)
    s = [0] * T
    for off in range(0, len(padded), RATE):
        for j in range(RATE):
            s[j] = (s[j] + padded[off + j]) % P
        s = permute(s)
    return s[:4]


def rc_admission_ticket_hash(block_hash, nonce):
    """Poseidon2-GL12("BTX_RC_ADMIT_P2_V1" || block_hash || nonce_le64) as an int."""
    preimage = ADMISSION_DOMAIN + ser_uint256(block_hash) + struct.pack("<Q", nonce)
    lanes = [len(preimage)]
    for off in range(0, len(preimage), 7):
        lanes.append(int.from_bytes(preimage[off:off + 7], "little"))
    digest = sponge_hash(lanes)
    return int.from_bytes(b"".join(struct.pack("<Q", v) for v in digest), "little")


def rc_admission_target(nbits, pow_limit=(1 << 256) - 1):
    raw = uint256_from_compact(nbits)
    if raw >> (256 - ADMISSION_NBITS_DISCOUNT):
        raw = pow_limit
    else:
        raw <<= ADMISSION_NBITS_DISCOUNT
    hardest = (1 << (256 - ADMISSION_MAX_WORK_BITS)) - 1
    easiest = (1 << (256 - ADMISSION_MIN_WORK_BITS)) - 1
    return min(max(raw, hardest), easiest)


def grind_rc_admission_ticket(block, max_tries=1 << 24):
    """Return a ticket nonce for block (a rehashed CBlock or CBlockHeader)."""
    target = rc_admission_target(block.nBits)
    for nonce in range(max_tries):
        if rc_admission_ticket_hash(block.sha256, nonce) <= target:
            return nonce
    raise AssertionError("no RCADMIT ticket found")


class msg_rcadmit:
    __slots__ = ("block_hash", "nonce")
    msgtype = b"rcadmit"

    def __init__(self, block_hash=0, nonce=0):
        self.block_hash = block_hash
        self.nonce = nonce

    def serialize(self):
        return ser_uint256(self.block_hash) + struct.pack("<Q", self.nonce)

    def __repr__(self):
        return f"msg_rcadmit(block_hash={self.block_hash:064x} nonce={self.nonce})"


# Frozen vectors from src/test/matmul_v4_rc_alg_hash_tests.cpp.
assert permute([0] * T)[0] == 0x2287c4d3bf1f9fcf
assert permute(list(range(T)))[11] == 0xd65d44c6e711b816
