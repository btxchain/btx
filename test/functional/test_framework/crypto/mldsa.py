#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test-only pure Python ML-DSA-44 (FIPS 204) key generation and signing.

WARNING: This code is slow, uses no constant-time arithmetic and keeps keys in
plain Python objects. It exists so the functional test framework can create
P2MR spends (OP_CHECKSIG_MLDSA) without a node wallet. Do not use it for
anything else.

Signatures are produced by the deterministic variant (rnd = 32 zero bytes) of
ML-DSA.Sign with an empty context string, i.e. the message representative is
M' = 0x00 || 0x00 || M. This is what the node verifies through libbitcoinpqc
(pq-crystals reference code, ML-DSA-44).

Polynomial products use Kronecker substitution on Python integers instead of
the NTT: the matrix A is sampled in the NTT domain as the standard requires,
converted to normal form once per key, and every product after that is a
single big-integer multiplication.
"""

import hashlib
import struct
import unittest

Q = 8380417
N = 256
D = 13
TAU = 39
LAMBDA = 128
GAMMA1 = 1 << 17
GAMMA2 = (Q - 1) // 88
K = 4
L = 4
ETA = 2
BETA = TAU * ETA
OMEGA = 80

PUBKEY_SIZE = 32 + K * N * 10 // 8
SIGNATURE_SIZE = LAMBDA // 4 + L * N * 18 // 8 + OMEGA + K
assert PUBKEY_SIZE == 1312
assert SIGNATURE_SIZE == 2420

# ζ^brv8(k) mod q for k = 0..255, with ζ = 1753 (FIPS 204, Appendix B).
ZETAS = [pow(1753, int(f"{k:08b}"[::-1], 2), Q) for k in range(N)]
INV_256 = 8347681  # 256^-1 mod q
assert (INV_256 * 256) % Q == 1

SLOT_BYTES = 8  # Kronecker slot: 256 * (q-1)^2 * 4 < 2^64


def shake128(data, length):
    return hashlib.shake_128(data).digest(length)


def shake256(data, length):
    return hashlib.shake_256(data).digest(length)


def ntt(f):
    """FIPS 204 Algorithm 41."""
    w = list(f)
    m = 0
    length = 128
    while length >= 1:
        start = 0
        while start < N:
            m += 1
            z = ZETAS[m]
            for j in range(start, start + length):
                t = (z * w[j + length]) % Q
                w[j + length] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
            start += 2 * length
        length //= 2
    return w


def ntt_inverse(w_hat):
    """FIPS 204 Algorithm 42."""
    w = list(w_hat)
    m = N
    length = 1
    while length < N:
        start = 0
        while start < N:
            m -= 1
            z = Q - ZETAS[m]
            for j in range(start, start + length):
                t = w[j]
                w[j] = (t + w[j + length]) % Q
                w[j + length] = (z * (t - w[j + length])) % Q
            start += 2 * length
        length *= 2
    return [(INV_256 * x) % Q for x in w]


def to_int(poly):
    """Pack a polynomial (coefficients taken mod q) into one Python integer."""
    return int.from_bytes(struct.pack(f"<{N}Q", *[c % Q for c in poly]), "little")


def from_int(value):
    """Unpack a Kronecker product and reduce it modulo X^256 + 1 and q."""
    c = struct.unpack(f"<{2 * N}Q", value.to_bytes(2 * N * SLOT_BYTES, "little"))
    return [(c[i] - c[i + N]) % Q for i in range(N)]


def centered(x):
    """Representative of x mod q in (-(q-1)/2, (q-1)/2]."""
    x %= Q
    return x - Q if x > (Q - 1) // 2 else x


def inf_norm(polys):
    return max(abs(centered(c)) for p in polys for c in p)


def rej_ntt_poly(seed):
    """FIPS 204 Algorithm 30 (coefficients in the NTT domain)."""
    stream = shake128(seed, 1680)
    coeffs = []
    pos = 0
    while len(coeffs) < N:
        if pos + 3 > len(stream):
            stream = shake128(seed, 2 * len(stream))
        b0, b1, b2 = stream[pos], stream[pos + 1], stream[pos + 2]
        pos += 3
        candidate = b0 | (b1 << 8) | ((b2 & 0x7F) << 16)
        if candidate < Q:
            coeffs.append(candidate)
    return coeffs


def rej_bounded_poly(seed):
    """FIPS 204 Algorithm 31 for η = 2."""
    stream = shake256(seed, 272)
    coeffs = []
    pos = 0
    while len(coeffs) < N:
        if pos >= len(stream):
            stream = shake256(seed, 2 * len(stream))
        z = stream[pos]
        pos += 1
        for half in (z & 0x0F, z >> 4):
            if half < 15 and len(coeffs) < N:
                coeffs.append(2 - (half % 5))
    return coeffs


def expand_a(rho):
    """FIPS 204 Algorithm 32: A_hat[r][s] = RejNTTPoly(rho || s || r)."""
    return [[rej_ntt_poly(rho + bytes([s, r])) for s in range(L)] for r in range(K)]


def expand_mask(rho2, kappa):
    """FIPS 204 Algorithm 34 for γ1 = 2^17 (18-bit coefficients)."""
    y = []
    mask = (1 << 18) - 1
    for r in range(L):
        v = int.from_bytes(shake256(rho2 + (kappa + r).to_bytes(2, "little"), 576), "little")
        y.append([GAMMA1 - ((v >> (18 * i)) & mask) for i in range(N)])
    return y


def sample_in_ball(seed):
    """FIPS 204 Algorithm 29."""
    stream = shake256(seed, 8 + 4 * 136)
    signs = int.from_bytes(stream[:8], "little")
    pos = 8
    c = [0] * N
    for i in range(N - TAU, N):
        while True:
            if pos >= len(stream):
                stream = shake256(seed, 2 * len(stream))
            j = stream[pos]
            pos += 1
            if j <= i:
                break
        c[i] = c[j]
        c[j] = 1 - 2 * (signs & 1)
        signs >>= 1
    return c


def decompose(r):
    """FIPS 204 Algorithm 36 (returns r1, r0 with r0 centered)."""
    r %= Q
    r0 = r % (2 * GAMMA2)
    if r0 > GAMMA2:
        r0 -= 2 * GAMMA2
    if r - r0 == Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * GAMMA2), r0


def high_bits(r):
    return decompose(r)[0]


def low_bits(r):
    return decompose(r)[1]


def use_hint(h, r):
    """FIPS 204 Algorithm 40 (used by the self-check verifier)."""
    m = (Q - 1) // (2 * GAMMA2)
    r1, r0 = decompose(r)
    if h == 1 and r0 > 0:
        return (r1 + 1) % m
    if h == 1 and r0 <= 0:
        return (r1 - 1) % m
    return r1


def pack_bits(values, bits):
    """SimpleBitPack/BitPack core: little-endian bit order."""
    acc = 0
    for i, v in enumerate(values):
        acc |= v << (bits * i)
    return acc.to_bytes(len(values) * bits // 8, "little")


def unpack_bits(data, bits, count):
    v = int.from_bytes(data, "little")
    mask = (1 << bits) - 1
    return [(v >> (bits * i)) & mask for i in range(count)]


def w1_encode(w1):
    return b"".join(pack_bits(p, 6) for p in w1)


def hint_bit_pack(h):
    y = bytearray(OMEGA + K)
    index = 0
    for i in range(K):
        for j in range(N):
            if h[i][j]:
                y[index] = j
                index += 1
        y[OMEGA + i] = index
    return bytes(y)


def hint_bit_unpack(y):
    h = [[0] * N for _ in range(K)]
    index = 0
    for i in range(K):
        if y[OMEGA + i] < index or y[OMEGA + i] > OMEGA:
            return None
        first = index
        while index < y[OMEGA + i]:
            if index > first and y[index - 1] >= y[index]:
                return None
            h[i][y[index]] = 1
            index += 1
    if any(y[i] != 0 for i in range(index, OMEGA)):
        return None
    return h


def mat_vec(a_int, v_int):
    """Rows of A times the vector v, with all products in Kronecker form."""
    return [from_int(sum(a * v for a, v in zip(row, v_int))) for row in a_int]


class MLDSA44Key:
    """An ML-DSA-44 key pair derived from a 32-byte seed (FIPS 204 KeyGen_internal)."""

    def __init__(self, seed):
        assert len(seed) == 32
        expanded = shake256(seed + bytes([K, L]), 128)
        rho, rho1, self._key = expanded[:32], expanded[32:96], expanded[96:]
        self._a_int = [[to_int(ntt_inverse(a)) for a in row] for row in expand_a(rho)]
        s1 = [rej_bounded_poly(rho1 + r.to_bytes(2, "little")) for r in range(L)]
        s2 = [rej_bounded_poly(rho1 + (L + r).to_bytes(2, "little")) for r in range(K)]
        t = [[(x + e) % Q for x, e in zip(row, s2[i])]
             for i, row in enumerate(mat_vec(self._a_int, [to_int(p) for p in s1]))]
        t1 = [[(x + (1 << (D - 1)) - 1) >> D for x in p] for p in t]
        t0 = [[x - (h << D) for x, h in zip(p, ph)] for p, ph in zip(t, t1)]
        self.pubkey = rho + b"".join(pack_bits(p, 10) for p in t1)
        assert len(self.pubkey) == PUBKEY_SIZE
        self._tr = shake256(self.pubkey, 64)
        self._s1_int = [to_int(p) for p in s1]
        self._s2_int = [to_int(p) for p in s2]
        self._t0_int = [to_int(p) for p in t0]

    def sign(self, msg):
        """Deterministic ML-DSA.Sign(sk, msg, ctx=b"")."""
        mu = shake256(self._tr + b"\x00\x00" + msg, 64)
        rho2 = shake256(self._key + bytes(32) + mu, 64)
        kappa = 0
        while True:
            y = expand_mask(rho2, kappa)
            kappa += L
            w = mat_vec(self._a_int, [to_int(p) for p in y])
            w1 = [[high_bits(x) for x in p] for p in w]
            c_tilde = shake256(mu + w1_encode(w1), LAMBDA // 4)
            c_int = to_int(sample_in_ball(c_tilde))
            z = [[yi + centered(ci) for yi, ci in zip(yp, from_int(c_int * s))]
                 for yp, s in zip(y, self._s1_int)]
            if max(abs(x) for p in z for x in p) >= GAMMA1 - BETA:
                continue
            cs2 = [from_int(c_int * s) for s in self._s2_int]
            w_cs2 = [[(x - e) % Q for x, e in zip(wp, ep)] for wp, ep in zip(w, cs2)]
            if inf_norm([[low_bits(x) for x in p] for p in w_cs2]) >= GAMMA2 - BETA:
                continue
            ct0 = [from_int(c_int * t) for t in self._t0_int]
            if inf_norm(ct0) >= GAMMA2:
                continue
            h = [[int(high_bits(r) != high_bits(r + ct)) for r, ct in zip(rp, cp)]
                 for rp, cp in zip(w_cs2, ct0)]
            if sum(map(sum, h)) > OMEGA:
                continue
            sig = c_tilde + b"".join(pack_bits([GAMMA1 - x for x in p], 18) for p in z) + hint_bit_pack(h)
            assert len(sig) == SIGNATURE_SIZE
            return sig


def verify(pubkey, msg, sig):
    """ML-DSA.Verify(pk, msg, sig, ctx=b"") using the NTT, independent of the signer's arithmetic."""
    if len(pubkey) != PUBKEY_SIZE or len(sig) != SIGNATURE_SIZE:
        return False
    rho = pubkey[:32]
    t1 = [unpack_bits(pubkey[32 + 320 * i:32 + 320 * (i + 1)], 10, N) for i in range(K)]
    c_tilde = sig[:LAMBDA // 4]
    off = LAMBDA // 4
    z = [[GAMMA1 - v for v in unpack_bits(sig[off + 576 * i:off + 576 * (i + 1)], 18, N)] for i in range(L)]
    h = hint_bit_unpack(sig[off + 576 * L:])
    if h is None or max(abs(x) for p in z for x in p) >= GAMMA1 - BETA:
        return False
    a_hat = expand_a(rho)
    tr = shake256(pubkey, 64)
    mu = shake256(tr + b"\x00\x00" + msg, 64)
    c_hat = ntt(sample_in_ball(c_tilde))
    z_hat = [ntt([x % Q for x in p]) for p in z]
    w1 = []
    for i in range(K):
        acc = [0] * N
        for j in range(L):
            acc = [(a + b * c) % Q for a, b, c in zip(acc, a_hat[i][j], z_hat[j])]
        t1_hat = ntt([(x << D) % Q for x in t1[i]])
        acc = ntt_inverse([(a - c * t) % Q for a, c, t in zip(acc, c_hat, t1_hat)])
        w1.append([use_hint(hb, x) for hb, x in zip(h[i], acc)])
    return shake256(mu + w1_encode(w1), LAMBDA // 4) == c_tilde


class TestFrameworkMLDSA(unittest.TestCase):
    def test_ntt_roundtrip(self):
        poly = [(i * 7919 + 13) % Q for i in range(N)]
        self.assertEqual(ntt_inverse(ntt(poly)), poly)

    def test_kronecker_matches_ntt(self):
        a = [(i * i + 3) % Q for i in range(N)]
        b = [(Q - 1 - i * 5) % Q for i in range(N)]
        via_ntt = ntt_inverse([x * y % Q for x, y in zip(ntt(a), ntt(b))])
        self.assertEqual(from_int(to_int(a) * to_int(b)), via_ntt)

    def test_sign_verify(self):
        key = MLDSA44Key(bytes(range(32)))
        msg = bytes(32)
        sig = key.sign(msg)
        self.assertTrue(verify(key.pubkey, msg, sig))
        self.assertFalse(verify(key.pubkey, bytes([1]) + msg[1:], sig))
        self.assertEqual(sig, key.sign(msg))  # deterministic

    def test_known_answer(self):
        # Seed 00..1f and the 32-byte message 00..00, checked against the
        # pq-crystals ML-DSA-44 reference code (src/libbitcoinpqc/dilithium/ref)
        # built with deterministic signing.
        key = MLDSA44Key(bytes(range(32)))
        sig = key.sign(bytes(32))
        self.assertEqual(hashlib.sha256(key.pubkey).hexdigest(), KAT_PUBKEY_SHA256)
        self.assertEqual(hashlib.sha256(sig).hexdigest(), KAT_SIGNATURE_SHA256)


KAT_PUBKEY_SHA256 = "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46"
KAT_SIGNATURE_SHA256 = "c59941604dd8eb958dd33951196d95c789e5de40b11e18a63fc476289a756410"
