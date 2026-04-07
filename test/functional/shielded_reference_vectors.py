#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Independent Python reference implementation of lattice crypto primitives
used by the BTX shielded transaction system.

This script computes reference test vectors for conformance checking
against the C++ implementation in src/shielded/lattice/.

Usage:
    python3 test/functional/shielded_reference_vectors.py

Constants match src/shielded/lattice/params.h exactly.
"""

import hashlib
import struct
import sys

# ---------------------------------------------------------------------------
# Constants (must match params.h)
# ---------------------------------------------------------------------------
POLY_N = 256
POLY_Q = 8380417
QINV = 58728449       # q^{-1} mod 2^32
MONT = 4193792         # 2^32 mod q (Montgomery constant R = 2^32 mod q)
MODULE_RANK = 4
BETA_CHALLENGE = 60
GAMMA_RESPONSE = 131072  # 1 << 17
VALUE_BITS = 51

# Dilithium NTT twiddle factors -- copied directly from the Dilithium
# reference implementation (src/libbitcoinpqc/dilithium/ref/ntt.c).
# These are already in Montgomery representation (multiplied by R=2^32 mod q).
ZETAS = [
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782,
]


# ---------------------------------------------------------------------------
# Montgomery arithmetic
# ---------------------------------------------------------------------------
def montgomery_reduce(a):
    """
    Montgomery reduction: given 64-bit a, return a * 2^{-32} mod q.
    Matches pqcrystals_dilithium2_ref_montgomery_reduce exactly.
    """
    # t = (int32_t)(a * QINV)  -- low 32 bits, interpreted as signed
    t = (a * QINV) % (1 << 32)
    if t >= (1 << 31):
        t -= (1 << 32)
    return (a - t * POLY_Q) >> 32


def reduce32(a):
    """Barrett-like reduction used in Dilithium: reduce to centered representative."""
    t = (a + (1 << 22)) >> 23
    t = a - t * POLY_Q
    return t


def caddq(a):
    """Conditionally add q to map negative values to [0, q)."""
    if a < 0:
        a += POLY_Q
    return a


def freeze(a):
    """Fully reduce to canonical [0, q) range."""
    return caddq(reduce32(a))


# ---------------------------------------------------------------------------
# NTT / Inverse NTT (Dilithium reference style)
# ---------------------------------------------------------------------------
def ntt(coeffs):
    """Forward NTT matching Dilithium reference (returns new list)."""
    a = list(coeffs)
    k = 0
    length = 128
    while length >= 1:
        start = 0
        while start < POLY_N:
            k += 1
            zeta = ZETAS[k]
            for j in range(start, start + length):
                t = montgomery_reduce(zeta * a[j + length])
                a[j + length] = a[j] - t
                a[j] = a[j] + t
            start += 2 * length
        length //= 2
    return a


def invntt_tomont(coeffs):
    """Inverse NTT with Montgomery factor, matching Dilithium reference."""
    a = list(coeffs)
    k = POLY_N
    length = 1
    while length < POLY_N:
        start = 0
        while start < POLY_N:
            k -= 1
            zeta = -ZETAS[k]
            for j in range(start, start + length):
                t = a[j]
                a[j] = t + a[j + length]
                a[j + length] = t - a[j + length]
                a[j + length] = montgomery_reduce(zeta * a[j + length])
            start += 2 * length
        length *= 2

    # Multiply by f = mont^2/256 mod q = 41978
    f = 41978
    for i in range(POLY_N):
        a[i] = montgomery_reduce(f * a[i])

    return a


# ---------------------------------------------------------------------------
# Polynomial operations
# ---------------------------------------------------------------------------
def poly_pointwise_mul(a, b):
    """Pointwise multiplication in NTT domain with Montgomery reduction."""
    return [montgomery_reduce(a[i] * b[i]) for i in range(POLY_N)]


def poly_mul(a, b):
    """
    Ring multiplication via NTT: a * b in Z_q[X]/(X^256+1).

    Note: The NTT/InvNTT round-trip introduces a Montgomery factor.
    Specifically, NTT(a) produces a_hat where a_hat[i] = a(zeta_i).
    Pointwise mul of a_hat*b_hat with Montgomery reduction gives
    c_hat[i] = a_hat[i]*b_hat[i]*R^{-1}. Then invntt_tomont multiplies
    by R/N. Net effect: result = a*b * R^{-1} * R/N * R^{-1} ... etc.

    To get the correct result without extra Montgomery factors, we
    use schoolbook multiplication as the reference. This avoids subtle
    Montgomery-domain bookkeeping and serves as a truly independent check.
    """
    c = [0] * POLY_N
    for i in range(POLY_N):
        if a[i] == 0:
            continue
        for j in range(POLY_N):
            if b[j] == 0:
                continue
            idx = i + j
            if idx < POLY_N:
                c[idx] = (c[idx] + a[i] * b[j]) % POLY_Q
            else:
                # X^N = -1 mod (X^N + 1)
                c[idx - POLY_N] = (c[idx - POLY_N] - a[i] * b[j]) % POLY_Q
    return c


def poly_add(a, b):
    """Coefficient-wise addition mod q."""
    return [(a[i] + b[i]) % POLY_Q for i in range(POLY_N)]


def poly_sub(a, b):
    """Coefficient-wise subtraction mod q."""
    return [(a[i] - b[i]) % POLY_Q for i in range(POLY_N)]


def poly_scale(poly, scalar):
    """Multiply all coefficients by scalar (mod q)."""
    s = scalar % POLY_Q
    return [(c * s) % POLY_Q for c in poly]


def poly_from_constant(value):
    """Polynomial with only the constant term set."""
    p = [0] * POLY_N
    p[0] = value % POLY_Q
    return p


# ---------------------------------------------------------------------------
# Deterministic PRNG (matches BTX's DeriveSeed + FastRandomContext usage)
# ---------------------------------------------------------------------------
def derive_seed(input_bytes, nonce, domain):
    """Match the C++ DeriveSeed function: SHA256(domain || input || LE32(nonce))."""
    nonce_le = struct.pack('<I', nonce)
    h = hashlib.sha256()
    h.update(domain.encode('ascii'))
    h.update(input_bytes)
    h.update(nonce_le)
    return h.digest()


# ---------------------------------------------------------------------------
# Challenge sampling
# ---------------------------------------------------------------------------
def sample_challenge_ref(transcript):
    """
    Reference implementation of SampleChallenge.

    Uses Fisher-Yates partial shuffle with BETA_CHALLENGE=60 non-zero
    coefficients, each +/-1, deterministically derived from the transcript.

    NOTE: This uses SHA256-based PRNG rather than ChaCha20 (FastRandomContext),
    so the exact coefficient positions will differ from the C++ output.
    The structural properties (weight, ternary) are verified independently.
    """
    challenge = [0] * POLY_N

    # Use SHA256 as a simple deterministic source for the reference
    seed = derive_seed(transcript, 0, "BTX_MatRiCT_Challenge_V2")

    # Simple PRNG from seed for reference (NOT matching ChaCha20)
    state = seed
    def next_rand(bound):
        nonlocal state
        state = hashlib.sha256(state).digest()
        val = int.from_bytes(state[:8], 'little')
        return val % bound

    indices = list(range(POLY_N))
    for i in range(BETA_CHALLENGE):
        j = i + next_rand(POLY_N - i)
        indices[i], indices[j] = indices[j], indices[i]
        sign = 1 if (next_rand(2) == 1) else -1
        challenge[indices[i]] = sign

    return challenge


def verify_challenge_structure(challenge):
    """Verify structural properties of a challenge polynomial."""
    nonzero = sum(1 for c in challenge if c != 0)
    all_ternary = all(c in (-1, 0, 1) for c in challenge)
    return nonzero == BETA_CHALLENGE and all_ternary


# ---------------------------------------------------------------------------
# Commitment computation: C = A*r + g*v (mod q)
# ---------------------------------------------------------------------------
def compute_commitment_ref(matrix_a, generator_g, value, blind_r):
    """
    Compute lattice Pedersen commitment: C = A*r + g*v.

    matrix_a: MODULE_RANK x MODULE_RANK matrix of polynomials
    generator_g: MODULE_RANK-length vector of polynomials
    value: integer value to commit
    blind_r: MODULE_RANK-length blinding vector of polynomials

    Returns MODULE_RANK-length vector of polynomials (each in [0, q)).
    """
    result = []
    for row in range(MODULE_RANK):
        # A[row] * r (inner product)
        acc = [0] * POLY_N
        for col in range(MODULE_RANK):
            term = poly_mul(matrix_a[row][col], blind_r[col])
            acc = poly_add(acc, term)

        # + g[row] * v
        g_scaled = poly_scale(generator_g[row], value)
        acc = poly_add(acc, g_scaled)

        result.append(acc)

    return result


# ---------------------------------------------------------------------------
# Test vector generation
# ---------------------------------------------------------------------------
def print_hex(label, data):
    """Print data as hex string."""
    if isinstance(data, (bytes, bytearray)):
        print(f"  {label}: {data.hex()}")
    elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], int):
        # Polynomial coefficients as LE int32
        raw = b''.join(struct.pack('<i', c) for c in data)
        print(f"  {label}: {raw[:64].hex()}...")
        print(f"    (first 16 coeffs: {data[:16]})")


def generate_ntt_roundtrip_vector():
    """Test vector: NTT then InverseNTT returns original polynomial."""
    print("=" * 70)
    print("TEST VECTOR: NTT Round-trip")
    print("=" * 70)

    # Simple polynomial: f(X) = 1 + 2X + 3X^2
    original = [0] * POLY_N
    original[0] = 1
    original[1] = 2
    original[2] = 3

    print("  Input polynomial (first 8 coeffs):", original[:8])

    forward = ntt(list(original))
    print("  After NTT (first 8 coeffs):", forward[:8])

    recovered = invntt_tomont(forward)
    print("  After InvNTT (first 8 coeffs):", [freeze(x) for x in recovered[:8]])

    # invntt_tomont(NTT(a)) produces a in Montgomery domain.
    # Each coefficient c becomes c * MONT mod q.
    # This is because the zetas are in Montgomery form, and the final
    # multiplication by f=41978=mont^2/256 leaves one factor of mont.
    expected = [(c * MONT) % POLY_Q for c in original]
    roundtrip_ok = all(
        freeze(recovered[i]) == expected[i] for i in range(POLY_N)
    )
    print(f"  Expected (original * MONT mod q, first 8): {expected[:8]}")
    print(f"  Round-trip correct (with Montgomery factor): {roundtrip_ok}")

    # Zero polynomial
    zero = [0] * POLY_N
    zero_fwd = ntt(list(zero))
    zero_rec = invntt_tomont(zero_fwd)
    zero_ok = all(freeze(zero_rec[i]) == 0 for i in range(POLY_N))
    print(f"  Zero polynomial round-trip correct: {zero_ok}")
    print()


def generate_challenge_structure_vector():
    """Test vector: challenge polynomial structure."""
    print("=" * 70)
    print("TEST VECTOR: Challenge Sampling Structure")
    print("=" * 70)

    transcript = b'\x01' * 32
    challenge = sample_challenge_ref(transcript)

    nonzero_count = sum(1 for c in challenge if c != 0)
    plus_count = sum(1 for c in challenge if c == 1)
    minus_count = sum(1 for c in challenge if c == -1)
    valid = verify_challenge_structure(challenge)

    print(f"  Transcript: {transcript.hex()}")
    print(f"  Non-zero coefficients: {nonzero_count} (expected {BETA_CHALLENGE})")
    print(f"  +1 count: {plus_count}, -1 count: {minus_count}")
    print(f"  Structure valid: {valid}")

    # Show positions of non-zero coefficients
    positions = [i for i, c in enumerate(challenge) if c != 0]
    print(f"  Non-zero positions (first 20): {positions[:20]}")

    # Second transcript
    transcript2 = b'\x02' * 32
    challenge2 = sample_challenge_ref(transcript2)
    valid2 = verify_challenge_structure(challenge2)
    differs = any(challenge[i] != challenge2[i] for i in range(POLY_N))
    print(f"  Different transcript produces different challenge: {differs}")
    print(f"  Second challenge structure valid: {valid2}")
    print()


def generate_poly_mul_vector():
    """Test vector: polynomial multiplication (schoolbook reference)."""
    print("=" * 70)
    print("TEST VECTOR: Polynomial Multiplication")
    print("=" * 70)

    # (1 + X)^2 = 1 + 2X + X^2 in Z_q[X]/(X^256+1)
    a = [0] * POLY_N
    a[0] = 1
    a[1] = 1

    c = poly_mul(a, a)
    print("  a(X) = 1 + X")
    print(f"  (a*a)(X) first 8 coeffs: {c[:8]}")
    print(f"  Expected:                [1, 2, 1, 0, 0, 0, 0, 0]")
    mul1_ok = c[:3] == [1, 2, 1] and all(x == 0 for x in c[3:])
    print(f"  Correct: {mul1_ok}")

    # X^255 * X = X^256 = -1 mod (X^256+1)
    a2 = [0] * POLY_N
    a2[255] = 1
    b2 = [0] * POLY_N
    b2[1] = 1

    c2 = poly_mul(a2, b2)
    print(f"\n  a(X) = X^255, b(X) = X")
    print(f"  (a*b)(X) first 4 coeffs: {c2[:4]}")
    print(f"  Expected: [{POLY_Q - 1}, 0, 0, 0]  (i.e., -1 mod q)")
    mul2_ok = c2[0] == POLY_Q - 1 and all(x == 0 for x in c2[1:])
    print(f"  Correct: {mul2_ok}")

    # Scalar multiplication: 7 * (1 + X + X^2) = 7 + 7X + 7X^2
    a3 = [0] * POLY_N
    a3[0] = 7
    b3 = [0] * POLY_N
    b3[0] = 1
    b3[1] = 1
    b3[2] = 1
    c3 = poly_mul(a3, b3)
    print(f"\n  a(X) = 7, b(X) = 1 + X + X^2")
    print(f"  (a*b)(X) first 8 coeffs: {c3[:8]}")
    mul3_ok = c3[:3] == [7, 7, 7] and all(x == 0 for x in c3[3:])
    print(f"  Correct: {mul3_ok}")
    print()


def generate_commitment_vector():
    """Test vector: commitment computation with known simple inputs."""
    print("=" * 70)
    print("TEST VECTOR: Commitment Structure")
    print("=" * 70)

    # Use simple identity matrix and g[i] = constant (i+1)
    # so the math is easily verifiable by hand.
    value = 42

    zero_blind = [[0] * POLY_N for _ in range(MODULE_RANK)]

    simple_gen = []
    for i in range(MODULE_RANK):
        g = [0] * POLY_N
        g[0] = i + 1
        simple_gen.append(g)

    simple_matrix = [[[0] * POLY_N for _ in range(MODULE_RANK)]
                     for _ in range(MODULE_RANK)]
    for i in range(MODULE_RANK):
        simple_matrix[i][i][0] = 1  # Identity with constant-1 diagonal

    # C = I*0 + g*42 = [42, 84, 126, 168]  (constant term of each component)
    commitment = compute_commitment_ref(simple_matrix, simple_gen, value, zero_blind)

    print(f"  Value: {value}")
    print(f"  Blinding: zero vector")
    print(f"  Matrix: identity,  Generator: g[i][0] = i+1")
    print(f"  Commitment (constant term per component):")
    all_ok = True
    for i in range(MODULE_RANK):
        expected = (value * (i + 1)) % POLY_Q
        ok = commitment[i][0] == expected
        all_ok = all_ok and ok
        print(f"    C[{i}][0] = {commitment[i][0]} (expected {expected}) {'OK' if ok else 'FAIL'}")

    # With non-zero blinding: C = I*r + g*v
    # C[i][0] = r[i][0] + g[i][0]*v = 100*(i+1) + (i+1)*42 = (i+1)*142
    blind = [[0] * POLY_N for _ in range(MODULE_RANK)]
    for i in range(MODULE_RANK):
        blind[i][0] = 100 * (i + 1)

    commitment2 = compute_commitment_ref(simple_matrix, simple_gen, value, blind)
    print(f"\n  With blinding r[i][0] = 100*(i+1):")
    for i in range(MODULE_RANK):
        expected = (100 * (i + 1) + value * (i + 1)) % POLY_Q
        ok = commitment2[i][0] == expected
        all_ok = all_ok and ok
        print(f"    C[{i}][0] = {commitment2[i][0]} (expected {expected}) {'OK' if ok else 'FAIL'}")

    print(f"  All commitment checks: {'PASS' if all_ok else 'FAIL'}")
    print()


def generate_balance_check_vector():
    """Test vector: balance equation check (sum inputs = sum outputs + fee)."""
    print("=" * 70)
    print("TEST VECTOR: Balance Equation")
    print("=" * 70)

    simple_gen = []
    for i in range(MODULE_RANK):
        g = [0] * POLY_N
        g[0] = i + 1
        simple_gen.append(g)

    simple_matrix = [[[0] * POLY_N for _ in range(MODULE_RANK)]
                     for _ in range(MODULE_RANK)]
    for i in range(MODULE_RANK):
        simple_matrix[i][i][0] = 1

    # Input: value=1000, blind=r1  with r1[i][0] = 7*(i+1)
    r1 = [[0] * POLY_N for _ in range(MODULE_RANK)]
    for i in range(MODULE_RANK):
        r1[i][0] = 7 * (i + 1)
    c_in = compute_commitment_ref(simple_matrix, simple_gen, 1000, r1)

    # Output: value=900, blind=r2  with r2[i][0] = 3*(i+1)
    r2 = [[0] * POLY_N for _ in range(MODULE_RANK)]
    for i in range(MODULE_RANK):
        r2[i][0] = 3 * (i + 1)
    c_out = compute_commitment_ref(simple_matrix, simple_gen, 900, r2)

    # Fee commitment: value=100, blind=0
    c_fee = compute_commitment_ref(simple_matrix, simple_gen, 100,
                                    [[0] * POLY_N for _ in range(MODULE_RANK)])

    # Balance: C_in - C_out - C_fee
    # = (I*r1 + g*1000) - (I*r2 + g*900) - (I*0 + g*100)
    # = I*(r1 - r2) + g*(1000 - 900 - 100)
    # = I*(r1 - r2) + g*0
    # = r1 - r2
    balance = []
    for i in range(MODULE_RANK):
        row = poly_sub(poly_sub(c_in[i], c_out[i]), c_fee[i])
        balance.append(row)

    print(f"  Input:  value=1000, blind[i][0]=7*(i+1)")
    print(f"  Output: value=900,  blind[i][0]=3*(i+1)")
    print(f"  Fee:    100")
    print(f"  Balance residual (constant term per component):")
    all_ok = True
    for i in range(MODULE_RANK):
        expected = (7 - 3) * (i + 1)  # r1 - r2
        ok = balance[i][0] == expected
        all_ok = all_ok and ok
        print(f"    balance[{i}][0] = {balance[i][0]} (expected {expected}) "
              f"{'OK' if ok else 'FAIL'}")

    # Verify all non-constant terms are zero
    higher_zero = all(balance[i][j] == 0
                      for i in range(MODULE_RANK)
                      for j in range(1, POLY_N))
    print(f"  Higher-order terms all zero: {higher_zero}")
    print(f"  Balance equation correct: {all_ok and higher_zero}")

    # Mismatched balance: wrong fee
    c_wrong_fee = compute_commitment_ref(simple_matrix, simple_gen, 99,
                                          [[0] * POLY_N for _ in range(MODULE_RANK)])
    bad_balance = []
    for i in range(MODULE_RANK):
        row = poly_sub(poly_sub(c_in[i], c_out[i]), c_wrong_fee[i])
        bad_balance.append(row)
    # With wrong fee, constant term should include leftover value
    print(f"\n  Wrong fee (99 instead of 100):")
    for i in range(MODULE_RANK):
        # residual = r1-r2 + g*(1000-900-99) = r1-r2 + g*1
        expected = ((7 - 3) * (i + 1) + (i + 1) * 1) % POLY_Q
        print(f"    balance[{i}][0] = {bad_balance[i][0]} (expected {expected}, "
              f"non-zero value residual)")
    print()


def generate_parameter_summary():
    """Print all parameters for cross-reference with params.h."""
    print("=" * 70)
    print("PARAMETER SUMMARY (must match src/shielded/lattice/params.h)")
    print("=" * 70)
    print(f"  POLY_N         = {POLY_N}")
    print(f"  POLY_Q         = {POLY_Q}")
    print(f"  POLY_Q (hex)   = 0x{POLY_Q:08x}")
    print(f"  QINV           = {QINV}")
    print(f"  MONT (R)       = {MONT}")
    print(f"  MODULE_RANK    = {MODULE_RANK}")
    print(f"  VALUE_BITS     = {VALUE_BITS}")
    print(f"  BETA_CHALLENGE = {BETA_CHALLENGE}")
    print(f"  GAMMA_RESPONSE = {GAMMA_RESPONSE}")

    max_money = 21_000_000 * 100_000_000
    print(f"  MAX_MONEY      = {max_money} satoshis")
    print(f"  MAX_MONEY bits = {max_money.bit_length()} "
          f"(must fit in VALUE_BITS={VALUE_BITS})")

    fits = max_money < (1 << VALUE_BITS)
    print(f"  MAX_MONEY < 2^VALUE_BITS: {fits}")
    print(f"  2^VALUE_BITS = {1 << VALUE_BITS}")

    # Verify Dilithium f constant
    f_computed = (MONT * MONT * pow(POLY_N, POLY_Q - 2, POLY_Q)) % POLY_Q
    print(f"  f = mont^2/N mod q = {f_computed} (Dilithium uses 41978)")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def generate_frozen_ntt_vectors():
    """
    Frozen NTT test vectors for cross-validation with C++ implementation.
    These vectors use deterministic inputs and produce exact expected outputs
    that MUST match the C++ NTT (Dilithium reference) output byte-for-byte.
    """
    print("=" * 70)
    print("FROZEN TEST VECTOR: NTT Cross-Validation")
    print("=" * 70)

    # Vector 1: unit polynomial X^k for several k values
    for k in [0, 1, 127, 255]:
        poly = [0] * POLY_N
        poly[k] = 1
        ntt_out = ntt(list(poly))
        # Hash the NTT output for compact cross-validation
        h = hashlib.sha256()
        for c in ntt_out:
            h.update(struct.pack('<i', c))
        digest = h.hexdigest()
        # NOTE: C++ uint256::GetHex() displays bytes in reverse order.
        # To compare with C++ test output, reverse the hex bytes:
        reversed_hex = bytes.fromhex(digest)[::-1].hex()
        print(f"  NTT(X^{k}) SHA256:          {digest}")
        print(f"  NTT(X^{k}) SHA256 (C++ LE): {reversed_hex}")
        print(f"    first 4 NTT coeffs: {ntt_out[:4]}")

    # Vector 2: NTT of constant polynomial 42
    poly42 = [0] * POLY_N
    poly42[0] = 42
    ntt42 = ntt(list(poly42))
    h = hashlib.sha256()
    for c in ntt42:
        h.update(struct.pack('<i', c))
    print(f"  NTT(42) SHA256: {h.hexdigest()}")

    # Vector 3: Pointwise mul of NTT(1+X) * NTT(1+X), then InvNTT
    a = [0] * POLY_N
    a[0] = 1
    a[1] = 1
    a_ntt = ntt(list(a))
    prod_ntt = poly_pointwise_mul(a_ntt, a_ntt)
    prod = invntt_tomont(prod_ntt)
    prod_frozen = [freeze(c) for c in prod]
    # Result should be (1+X)^2 = 1+2X+X^2 in Montgomery domain
    # i.e., coeffs * MONT mod q
    expected = [0] * POLY_N
    expected[0] = (1 * MONT) % POLY_Q
    expected[1] = (2 * MONT) % POLY_Q
    expected[2] = (1 * MONT) % POLY_Q
    match = all(prod_frozen[i] == expected[i] for i in range(POLY_N))
    print(f"  NTT-mul (1+X)^2 in Montgomery domain correct: {match}")

    print()


def generate_rejection_sampling_parameters():
    """Verify the rejection sampling parameter calculations."""
    print("=" * 70)
    print("FROZEN TEST VECTOR: Rejection Sampling Parameters")
    print("=" * 70)

    response_norm_bound = GAMMA_RESPONSE - BETA_CHALLENGE * 2  # SECRET_SMALL_ETA=2
    print(f"  GAMMA_RESPONSE = {GAMMA_RESPONSE}")
    print(f"  BETA_CHALLENGE = {BETA_CHALLENGE}")
    print(f"  SECRET_SMALL_ETA = 2")
    print(f"  RESPONSE_NORM_BOUND = γ - β·η = {GAMMA_RESPONSE} - {BETA_CHALLENGE}*2 = {response_norm_bound}")
    print(f"  RESPONSE_NORM_BOUND > 0: {response_norm_bound > 0}")
    print(f"  RESPONSE_NORM_BOUND < GAMMA_RESPONSE: {response_norm_bound < GAMMA_RESPONSE}")

    # Acceptance probability approximation
    # P(accept) ≈ (RESPONSE_NORM_BOUND / GAMMA_RESPONSE)^(MODULE_RANK * POLY_N)
    ratio = response_norm_bound / GAMMA_RESPONSE
    exponent = MODULE_RANK * POLY_N
    # More accurate: P ≈ ((2*RNB+1)/(2*GAMMA+1))^(rank*N) but ratio is close
    p_accept = ratio ** exponent
    print(f"  Approximate acceptance probability: {p_accept:.4f}")
    print(f"  Expected attempts (1/p): {1/p_accept:.1f}")
    print(f"  MAX_REJECTION_ATTEMPTS = 512")
    print(f"  Failure probability ≈ (1-p)^512 = {(1-p_accept)**512:.2e}")

    # Soundness of per-bit challenges
    bit_challenge_span = 2 * BETA_CHALLENGE + 1
    per_bit_soundness = bit_challenge_span
    combined_soundness = per_bit_soundness ** VALUE_BITS
    import math
    bits_security = math.log2(combined_soundness)
    print(f"\n  Per-bit challenge span: {bit_challenge_span}")
    print(f"  Combined soundness across {VALUE_BITS} bits: {combined_soundness:.2e}")
    print(f"  Bits of security: {bits_security:.1f}")
    print()


def generate_domain_separator_hashes():
    """Hash all domain separators to detect accidental changes."""
    print("=" * 70)
    print("FROZEN TEST VECTOR: Domain Separator Hashes")
    print("=" * 70)

    domain_separators = [
        "BTX_MatRiCT_Challenge_V2",
        "BTX_MatRiCT_UniformPoly_V1",
        "BTX_MatRiCT_Commit_A_V1",
        "BTX_MatRiCT_Commit_G_V1",
        "BTX_MatRiCT_RingSig_Challenge_V4",
        "BTX_MatRiCT_RingSig_FS_V3",
        "BTX_MatRiCT_RingSig_Msg_V1",
        "BTX_MatRiCT_RingSig_RNGSeed_V2",
        "BTX_MatRiCT_RingSig_SecretFromNote_V1",
        "BTX_MatRiCT_RingSig_Public_V5",
        "BTX_MatRiCT_RingSig_LinkBase_V4",
        "BTX_MatRiCT_RingSig_Nullifier_V1",
        "BTX_MatRiCT_BalanceProof_V2",
        "BTX_MatRiCT_BalanceProof_Nonce_V2",
        "BTX_MatRiCT_RangeProof_BitChallenge_V4",
        "BTX_MatRiCT_RangeProof_Relation_V4",
        "BTX_MatRiCT_RangeProof_Binding_V1",
        "BTX_MatRiCT_RangeProof_RNGSeed_V1",
        "BTX_MatRiCT_Proof_V2",
        "BTX_MatRiCT_InputBlind_V1",
        "BTX_MatRiCT_OutputBlind_V1",
        "BTX_Shielded_SpendAuth_V1",
    ]

    # Hash all separators together to create a frozen fingerprint
    combined = hashlib.sha256()
    for sep in sorted(domain_separators):
        sep_hash = hashlib.sha256(sep.encode('ascii')).hexdigest()
        combined.update(sep.encode('ascii'))
        print(f"  {sep}")
        print(f"    SHA256: {sep_hash}")

    print(f"\n  Combined domain separator fingerprint:")
    print(f"    SHA256: {combined.hexdigest()}")
    print(f"  Total domain separators: {len(domain_separators)}")
    print()


def run_assertions():
    """Run automated assertions for all reference vectors. Returns (pass_count, fail_count)."""
    passes = 0
    failures = 0

    def check(condition, description):
        nonlocal passes, failures
        if condition:
            passes += 1
        else:
            failures += 1
            print(f"  FAIL: {description}")

    # --- Parameter validation ---
    max_money = 21_000_000 * 100_000_000
    check(max_money < (1 << VALUE_BITS), "MAX_MONEY fits in VALUE_BITS")
    check(POLY_Q == 8380417, "POLY_Q matches Dilithium constant")
    check(POLY_N == 256, "POLY_N is 256")
    check(MODULE_RANK == 4, "MODULE_RANK is 4")

    # --- NTT round-trip ---
    original = [0] * POLY_N
    original[0] = 1
    original[1] = 2
    original[2] = 3
    forward = ntt(list(original))
    recovered = invntt_tomont(forward)
    expected_mont = [(c * MONT) % POLY_Q for c in original]
    roundtrip_ok = all(freeze(recovered[i]) == expected_mont[i] for i in range(POLY_N))
    check(roundtrip_ok, "NTT round-trip with Montgomery factor")

    zero = [0] * POLY_N
    zero_fwd = ntt(list(zero))
    zero_rec = invntt_tomont(zero_fwd)
    zero_ok = all(freeze(zero_rec[i]) == 0 for i in range(POLY_N))
    check(zero_ok, "Zero polynomial NTT round-trip")

    # --- Polynomial multiplication ---
    a = [0] * POLY_N
    a[0] = 1
    a[1] = 1
    c = poly_mul(a, a)
    check(c[:3] == [1, 2, 1] and all(x == 0 for x in c[3:]),
          "(1+X)^2 = 1 + 2X + X^2")

    a2 = [0] * POLY_N
    a2[255] = 1
    b2 = [0] * POLY_N
    b2[1] = 1
    c2 = poly_mul(a2, b2)
    check(c2[0] == POLY_Q - 1 and all(x == 0 for x in c2[1:]),
          "X^255 * X = -1 mod (X^256+1)")

    # --- Challenge structure ---
    transcript = b'\x01' * 32
    challenge = sample_challenge_ref(transcript)
    check(verify_challenge_structure(challenge), "Challenge has correct weight and ternary property")

    transcript2 = b'\x02' * 32
    challenge2 = sample_challenge_ref(transcript2)
    check(verify_challenge_structure(challenge2), "Second challenge has correct structure")
    check(any(challenge[i] != challenge2[i] for i in range(POLY_N)),
          "Different transcripts produce different challenges")

    # --- Commitment structure ---
    simple_gen = []
    for i in range(MODULE_RANK):
        g = [0] * POLY_N
        g[0] = i + 1
        simple_gen.append(g)

    simple_matrix = [[[0] * POLY_N for _ in range(MODULE_RANK)]
                     for _ in range(MODULE_RANK)]
    for i in range(MODULE_RANK):
        simple_matrix[i][i][0] = 1

    commitment = compute_commitment_ref(simple_matrix, simple_gen, 42,
                                         [[0] * POLY_N for _ in range(MODULE_RANK)])
    for i in range(MODULE_RANK):
        expected_val = (42 * (i + 1)) % POLY_Q
        check(commitment[i][0] == expected_val,
              f"Zero-blind commitment C[{i}][0] = {expected_val}")

    # --- Balance equation ---
    r1 = [[0] * POLY_N for _ in range(MODULE_RANK)]
    r2 = [[0] * POLY_N for _ in range(MODULE_RANK)]
    for i in range(MODULE_RANK):
        r1[i][0] = 7 * (i + 1)
        r2[i][0] = 3 * (i + 1)
    c_in = compute_commitment_ref(simple_matrix, simple_gen, 1000, r1)
    c_out = compute_commitment_ref(simple_matrix, simple_gen, 900, r2)
    c_fee = compute_commitment_ref(simple_matrix, simple_gen, 100,
                                    [[0] * POLY_N for _ in range(MODULE_RANK)])
    balance = []
    for i in range(MODULE_RANK):
        row = poly_sub(poly_sub(c_in[i], c_out[i]), c_fee[i])
        balance.append(row)
    for i in range(MODULE_RANK):
        check(balance[i][0] == (7 - 3) * (i + 1),
              f"Balance residual[{i}][0] = r1-r2")
    higher_zero = all(balance[i][j] == 0
                      for i in range(MODULE_RANK)
                      for j in range(1, POLY_N))
    check(higher_zero, "Balance higher-order terms all zero")

    # --- Frozen NTT cross-validation hashes ---
    unit_poly = [0] * POLY_N
    unit_poly[0] = 1
    ntt_unit = ntt(list(unit_poly))
    h = hashlib.sha256()
    for coeff in ntt_unit:
        h.update(struct.pack('<i', coeff))
    reversed_hex = bytes.fromhex(h.hexdigest())[::-1].hex()
    check(reversed_hex == "8b58fab50f40ff463e558ffec7c36b8354e719bf69217a6c6860758888c5f826",
          "NTT(1) frozen hash matches C++ KAT")

    poly42 = [0] * POLY_N
    poly42[0] = 42
    ntt42 = ntt(list(poly42))
    h42 = hashlib.sha256()
    for coeff in ntt42:
        h42.update(struct.pack('<i', coeff))
    reversed_hex42 = bytes.fromhex(h42.hexdigest())[::-1].hex()
    check(reversed_hex42 == "d31e315f0331b5756ceb58ea69abf2163abdeb7ef57475cd1533042974f8d568",
          "NTT(42) frozen hash matches C++ KAT")

    # --- Domain separator fingerprint ---
    domain_separators = [
        "BTX_MatRiCT_BalanceProof_Nonce_V2",
        "BTX_MatRiCT_BalanceProof_V2",
        "BTX_MatRiCT_Challenge_V2",
        "BTX_MatRiCT_Commit_A_V1",
        "BTX_MatRiCT_Commit_G_V1",
        "BTX_MatRiCT_InputBlind_V1",
        "BTX_MatRiCT_OutputBlind_V1",
        "BTX_MatRiCT_Proof_V2",
        "BTX_MatRiCT_RangeProof_Binding_V1",
        "BTX_MatRiCT_RangeProof_BitChallenge_V4",
        "BTX_MatRiCT_RangeProof_RNGSeed_V1",
        "BTX_MatRiCT_RangeProof_Relation_V4",
        "BTX_MatRiCT_RingSig_Challenge_V4",
        "BTX_MatRiCT_RingSig_FS_V3",
        "BTX_MatRiCT_RingSig_LinkBase_V4",
        "BTX_MatRiCT_RingSig_Msg_V1",
        "BTX_MatRiCT_RingSig_Nullifier_V1",
        "BTX_MatRiCT_RingSig_Public_V5",
        "BTX_MatRiCT_RingSig_RNGSeed_V2",
        "BTX_MatRiCT_RingSig_SecretFromNote_V1",
        "BTX_MatRiCT_UniformPoly_V1",
        "BTX_Shielded_SpendAuth_V1",
    ]
    combined = hashlib.sha256()
    for sep in domain_separators:
        combined.update(sep.encode('ascii'))
    check(combined.hexdigest() == "893f7f47bb5cc117682914e6ddf2dbc6508cc052ae1a8e07336617c9de9cb0fb",
          "Domain separator fingerprint matches C++ KAT")

    # --- Rejection sampling parameters ---
    response_norm_bound = GAMMA_RESPONSE - BETA_CHALLENGE * 2
    check(response_norm_bound > 0, "RESPONSE_NORM_BOUND > 0")
    check(response_norm_bound < GAMMA_RESPONSE, "RESPONSE_NORM_BOUND < GAMMA_RESPONSE")

    # Verify Dilithium f constant
    f_computed = (MONT * MONT * pow(POLY_N, POLY_Q - 2, POLY_Q)) % POLY_Q
    check(f_computed == 41978, "Dilithium f = mont^2/N mod q = 41978")

    return passes, failures


def main():
    print("BTX Shielded Lattice Crypto -- Reference Test Vectors")
    print("=" * 70)
    print()

    generate_parameter_summary()
    generate_ntt_roundtrip_vector()
    generate_poly_mul_vector()
    generate_challenge_structure_vector()
    generate_commitment_vector()
    generate_balance_check_vector()
    generate_frozen_ntt_vectors()
    generate_rejection_sampling_parameters()
    generate_domain_separator_hashes()

    print("=" * 70)
    print("Running automated assertions...")
    print("=" * 70)

    passes, failures = run_assertions()
    print(f"\nResults: {passes} passed, {failures} failed")

    if failures > 0:
        print("FAIL: Some reference vector checks did not pass.")
        return 1

    print("PASS: All reference vector checks passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
