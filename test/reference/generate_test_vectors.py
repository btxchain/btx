#!/usr/bin/env python3
"""
BTX MatMul PoW Reference Implementation and Test Vector Generator.

Implements all algorithms byte-exact per the BTX MatMul PoW specification
(doc/btx-matmul-pow-spec.md v3) and generates pinned + additional test vectors
as structured JSON.

Algorithms implemented:
  - reduce64: double Mersenne fold for M31
  - from_oracle(seed, index): SHA-256 PRF with rejection sampling
  - FromSeed(seed, n): row-major matrix generation
  - dot(a, b, length): per-step reduction inner product
  - Noise seed derivation: SHA-256(tag || sigma) for 4 domain tags
  - Compression vector: SHA-256("matmul-compress-v1" || sigma), b^2 elements
  - CanonicalMatMul_b with transcript compression and SHA-256d
"""

import hashlib
import json
import struct
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

M31 = 0x7FFFFFFF  # 2^31 - 1 = 2147483647, the Mersenne prime

# ---------------------------------------------------------------------------
# Field arithmetic over F_{M31}
# ---------------------------------------------------------------------------

def reduce64(x):
    """
    Reduces any uint64 value x in [0, 2^64) to [0, M31) via double Mersenne fold.

    Per spec section 7.2.3-7.2.4:
      FIRST FOLD:  fold1 = (x & M31) + (x >> 31)   -- stays in uint64
      SECOND FOLD: result = (fold1 & M31) + (fold1 >> 31)  -- fits uint32
      FINAL:       if result >= M31: result -= M31
    """
    assert 0 <= x < (1 << 64), f"reduce64 input out of range: {x}"
    # First fold: x can be up to 2^64-1
    fold1 = (x & M31) + (x >> 31)
    # fold1 is at most 5 * 2^31 - 2, fits in ~34 bits

    # Second fold
    lo = fold1 & M31
    hi = fold1 >> 31
    result = lo + hi
    # result is at most 2^31 + 3

    if result >= M31:
        result -= M31
    return result


def field_add(a, b):
    """(a + b) mod M31, inputs in [0, M31)."""
    s = a + b
    if s >= M31:
        s -= M31
    return s


def field_sub(a, b):
    """(a - b + M31) mod M31, inputs in [0, M31)."""
    if a >= b:
        return a - b
    else:
        return a + M31 - b


def field_mul(a, b):
    """(a * b) mod M31 via reduce64."""
    return reduce64(a * b)


def field_neg(a):
    """(-a) mod M31."""
    if a == 0:
        return 0
    return M31 - a


def dot(a, b, length):
    """
    Inner product with per-step reduction, per spec section 7.2.5.

    acc starts at 0 (in [0, M31)).
    Each iteration: acc = reduce64(acc + a[i]*b[i])

    This is safe for any length because acc < M31 < 2^31 and
    a[i]*b[i] < 2^62, so acc + product < 2^62.
    """
    acc = 0
    for i in range(length):
        product = a[i] * b[i]
        s = acc + product
        acc = reduce64(s)
    return acc


# ---------------------------------------------------------------------------
# SHA-256 helpers
# ---------------------------------------------------------------------------

def sha256(data):
    """Returns the SHA-256 digest of data as bytes."""
    return hashlib.sha256(data).digest()


def sha256d(data):
    """SHA-256d = SHA-256(SHA-256(data))."""
    return sha256(sha256(data))


def le32_bytes(val):
    """Encode a uint32 as 4 little-endian bytes."""
    return struct.pack('<I', val)


def le32_from_bytes(b):
    """Decode 4 little-endian bytes to uint32."""
    return struct.unpack('<I', b)[0]


def bytes_to_hex(b):
    """Convert bytes to hex string."""
    return b.hex()


def hex_to_bytes(h):
    """Convert hex string to bytes."""
    return bytes.fromhex(h)


# ---------------------------------------------------------------------------
# from_oracle and FromSeed
# ---------------------------------------------------------------------------

def from_oracle(seed_bytes, index):
    """
    from_oracle(seed, index) -> Element in [0, M31).

    Per spec section 7.4.1:
      retry = 0:  preimage = seed || LE32(index)           (36 bytes)
      retry > 0:  preimage = seed || LE32(index) || LE32(retry) (40 bytes)

      h = SHA-256(preimage)
      raw = h[0] | (h[1] << 8) | (h[2] << 16) | (h[3] << 24)   (LE uint32)
      candidate = raw & 0x7FFFFFFF
      if candidate < M31: return candidate
      else: retry += 1
    """
    assert len(seed_bytes) == 32, f"seed must be 32 bytes, got {len(seed_bytes)}"

    for retry in range(256):
        preimage = seed_bytes + le32_bytes(index)
        if retry > 0:
            preimage = preimage + le32_bytes(retry)

        h = sha256(preimage)

        # Extract bytes 0-3 as little-endian uint32
        raw = h[0] | (h[1] << 8) | (h[2] << 16) | (h[3] << 24)

        # Mask to 31 bits
        candidate = raw & 0x7FFFFFFF

        # Rejection sampling: reject candidate == M31
        if candidate < M31:
            return candidate

    raise RuntimeError("from_oracle: 256 consecutive rejections")


def from_seed(seed_bytes, n):
    """
    FromSeed(seed, n) -> n x n matrix (list of lists).

    Per spec section 7.4.3:
      M[row][col] = from_oracle(seed, row * n + col)
    Row-major indexing.
    """
    matrix = []
    for row in range(n):
        row_data = []
        for col in range(n):
            index = row * n + col
            row_data.append(from_oracle(seed_bytes, index))
        matrix.append(row_data)
    return matrix


def from_seed_rect(seed_bytes, rows, cols):
    """
    Generate a rows x cols matrix using from_oracle with row-major indexing.
    Index = row * cols + col (uses column count of this matrix as stride).
    """
    matrix = []
    for row in range(rows):
        row_data = []
        for col in range(cols):
            index = row * cols + col
            row_data.append(from_oracle(seed_bytes, index))
        matrix.append(row_data)
    return matrix


# ---------------------------------------------------------------------------
# Matrix arithmetic over M31
# ---------------------------------------------------------------------------

def mat_zeros(rows, cols):
    """Create a rows x cols zero matrix."""
    return [[0] * cols for _ in range(rows)]


def mat_add(A, B):
    """Element-wise field addition of two matrices."""
    rows = len(A)
    cols = len(A[0])
    return [[field_add(A[r][c], B[r][c]) for c in range(cols)] for r in range(rows)]


def mat_sub(A, B):
    """Element-wise field subtraction of two matrices."""
    rows = len(A)
    cols = len(A[0])
    return [[field_sub(A[r][c], B[r][c]) for c in range(cols)] for r in range(rows)]


def mat_mul(A, B):
    """
    Matrix multiplication over M31 using dot() for each output element.
    A is m x p, B is p x n -> result is m x n.
    """
    m = len(A)
    p = len(A[0])
    n = len(B[0])
    assert len(B) == p

    C = mat_zeros(m, n)
    for i in range(m):
        for j in range(n):
            a_vec = [A[i][k] for k in range(p)]
            b_vec = [B[k][j] for k in range(p)]
            C[i][j] = dot(a_vec, b_vec, p)
    return C


def mat_block_get(M, bi, bj, b):
    """Extract the (bi, bj)-th b x b block from matrix M."""
    result = []
    for r in range(b):
        row = []
        for c in range(b):
            row.append(M[bi * b + r][bj * b + c])
        result.append(row)
    return result


def mat_block_set(M, bi, bj, b, block):
    """Set the (bi, bj)-th b x b block in matrix M."""
    for r in range(b):
        for c in range(b):
            M[bi * b + r][bj * b + c] = block[r][c]


def mat_flatten(block):
    """Flatten a 2D matrix to a 1D list (row-major)."""
    result = []
    for row in block:
        result.extend(row)
    return result


# ---------------------------------------------------------------------------
# Noise generation
# ---------------------------------------------------------------------------

NOISE_TAGS = {
    'EL': b'matmul_noise_EL_v1',
    'ER': b'matmul_noise_ER_v1',
    'FL': b'matmul_noise_FL_v1',
    'FR': b'matmul_noise_FR_v1',
}


def derive_noise_seed(tag_key, sigma_bytes):
    """
    Derive a noise factor seed per spec section 8.2.1:
      tag_XX = SHA-256(domain_tag || sigma)
    where domain_tag is raw ASCII bytes (no null terminator).
    """
    tag = NOISE_TAGS[tag_key]
    preimage = tag + sigma_bytes
    return sha256(preimage)


def generate_noise(sigma_bytes, n, r):
    """
    Generate all four noise factor matrices per spec section 8.2.1.

    Returns dict with keys 'EL', 'ER', 'FL', 'FR', each a 2D list.
      EL: n x r  (index = row * r + col)
      ER: r x n  (index = row * n + col)
      FL: n x r  (index = row * r + col)
      FR: r x n  (index = row * n + col)
    """
    tag_EL = derive_noise_seed('EL', sigma_bytes)
    tag_ER = derive_noise_seed('ER', sigma_bytes)
    tag_FL = derive_noise_seed('FL', sigma_bytes)
    tag_FR = derive_noise_seed('FR', sigma_bytes)

    EL = from_seed_rect(tag_EL, n, r)
    ER = from_seed_rect(tag_ER, r, n)
    FL = from_seed_rect(tag_FL, n, r)
    FR = from_seed_rect(tag_FR, r, n)

    return {
        'EL': EL, 'ER': ER, 'FL': FL, 'FR': FR,
        'tag_EL': tag_EL, 'tag_ER': tag_ER,
        'tag_FL': tag_FL, 'tag_FR': tag_FR,
    }


# ---------------------------------------------------------------------------
# Transcript compression
# ---------------------------------------------------------------------------

COMPRESS_TAG = b'matmul-compress-v1'


def derive_compression_vector(sigma_bytes, b):
    """
    DeriveCompressionVector(sigma, b) per spec section 8.3.1:
      seed = SHA-256("matmul-compress-v1" || sigma)
      v[k] = from_oracle(seed, k) for k in 0..b^2-1
    Returns a list of b^2 field elements.
    """
    seed = sha256(COMPRESS_TAG + sigma_bytes)
    v = []
    for k in range(b * b):
        v.append(from_oracle(seed, k))
    return v


def compress_block(block_flat, v):
    """
    CompressBlock(block_bb_flat, v) per spec section 8.3.1:
      return dot(block_bb_flat, v, b*b)
    """
    assert len(block_flat) == len(v)
    return dot(block_flat, v, len(v))


# ---------------------------------------------------------------------------
# Canonical MatMul with streaming transcript hash
# ---------------------------------------------------------------------------

def canonical_matmul(A_prime, B_prime, b, sigma_bytes):
    """
    CanonicalMatMul_b(A', B') per spec sections 2.2 and 8.3.

    Performs block matmul with block size b, computes streaming transcript
    hash using SHA-256d over compressed intermediates.

    Returns (C_prime, transcript_hash_hex).
    """
    n = len(A_prime)
    assert n == len(A_prime[0]) == len(B_prime) == len(B_prime[0])
    assert n % b == 0

    N = n // b  # number of block rows/cols

    # Derive compression vector
    compress_vec = derive_compression_vector(sigma_bytes, b)

    # Initialize result matrix
    C_prime = mat_zeros(n, n)

    # Initialize rolling SHA-256 hasher (first pass of SHA-256d)
    # We accumulate all LE32 compressed elements, then do SHA-256(SHA-256(all))
    all_compressed_bytes = bytearray()

    # Canonical triple loop: i, j, ell
    for i in range(N):
        for j in range(N):
            for ell in range(N):
                # Get A'_block[i][ell] and B'_block[ell][j]
                A_block = mat_block_get(A_prime, i, ell, b)
                B_block = mat_block_get(B_prime, ell, j, b)

                # Compute the b x b product and add to C'_block[i][j]
                product = mat_mul(A_block, B_block)

                # Get current C'_block[i][j]
                C_block = mat_block_get(C_prime, i, j, b)

                # Accumulate: C'_block[i][j] += product
                C_block = mat_add(C_block, product)
                mat_block_set(C_prime, i, j, b, C_block)

                # Compress the intermediate and feed into transcript hash
                flat = mat_flatten(C_block)
                compressed = compress_block(flat, compress_vec)

                # Write LE32(compressed) into the rolling hash stream
                all_compressed_bytes += le32_bytes(compressed)

    # SHA-256d finalization
    inner_hash = sha256(bytes(all_compressed_bytes))
    transcript_hash = sha256(inner_hash)

    return C_prime, bytes_to_hex(transcript_hash)


# ---------------------------------------------------------------------------
# Verification of pinned test vectors from the spec
# ---------------------------------------------------------------------------

def verify_pinned_vectors():
    """Verify ALL pinned test vectors from the spec. Returns (pass_count, fail_count, messages)."""
    passes = 0
    fails = 0
    messages = []

    def check(name, actual, expected):
        nonlocal passes, fails
        if actual == expected:
            passes += 1
            messages.append(f"  PASS: {name}")
        else:
            fails += 1
            messages.append(f"  FAIL: {name}: expected {expected}, got {actual}")

    zero_seed = b'\x00' * 32

    # --- TV1: from_oracle(seed=0x00..00, index=0) ---
    # Spec: SHA-256 of 36 zero bytes = 6db65fd59fd356f6...
    preimage_tv1 = zero_seed + le32_bytes(0)
    h_tv1 = sha256(preimage_tv1)
    check("TV1 SHA-256 hash",
          bytes_to_hex(h_tv1),
          "6db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e")

    # Spec: bytes[0..3] = 6d b6 5f d5 -> wait, let me re-check
    # The spec says: "bytes[0..3]: 6d 5f b6 d5" but the hash is 6db65fd5...
    # Hash bytes: 6d b6 5f d5 9f d3 56 f6 ...
    # Wait - the spec says "bytes[0..3]: 6d 5f b6 d5" but looking at the hex string
    # "6db65fd59fd356f6..." the raw bytes are 0x6d, 0xb6, 0x5f, 0xd5 ...
    # The spec text "6d 5f b6 d5" appears to have a typo in the spacing.
    # Let me check: the hex string is 6db65fd5... which means bytes are:
    # h[0]=0x6d, h[1]=0xb6, h[2]=0x5f, h[3]=0xd5
    # LE uint32 = 0xd55fb66d
    check("TV1 LE uint32 from hash bytes",
          h_tv1[0] | (h_tv1[1] << 8) | (h_tv1[2] << 16) | (h_tv1[3] << 24),
          0xd55fb66d)

    check("TV1 masked candidate",
          0xd55fb66d & 0x7fffffff,
          0x555fb66d)

    check("TV1 from_oracle result",
          from_oracle(zero_seed, 0),
          1432335981)

    # --- TV2: from_oracle(seed=0x00..00, index=1) ---
    check("TV2 from_oracle(zero_seed, 1)",
          from_oracle(zero_seed, 1),
          1134348657)

    # Verify TV2 SHA-256
    preimage_tv2 = zero_seed + le32_bytes(1)
    h_tv2 = sha256(preimage_tv2)
    check("TV2 SHA-256 hash",
          bytes_to_hex(h_tv2),
          "71c99cc3bc21757feed5b712744ebb0f770d5c41d99189f9457495747bf11050")

    # --- TV3: from_oracle(seed=0x00..00, index=7) ---
    check("TV3 from_oracle(zero_seed, 7)",
          from_oracle(zero_seed, 7),
          2147021205)

    preimage_tv3 = zero_seed + le32_bytes(7)
    h_tv3 = sha256(preimage_tv3)
    check("TV3 SHA-256 hash",
          bytes_to_hex(h_tv3),
          "95f1f8ffe5b54fd46e622b34b93464acfc25fd54cabd50a3f0143479e4253b42")

    # --- TV4: from_oracle(seed=SHA-256("test_seed"), index=42) ---
    test_seed = sha256(b"test_seed")
    check("TV4 seed = SHA-256('test_seed')",
          bytes_to_hex(test_seed),
          "4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150")

    check("TV4 from_oracle(test_seed, 42)",
          from_oracle(test_seed, 42),
          1287506798)

    preimage_tv4 = test_seed + le32_bytes(42)
    h_tv4 = sha256(preimage_tv4)
    check("TV4 SHA-256 hash",
          bytes_to_hex(h_tv4),
          "6ecbbdccdae17aaac5acb50d7b23107f7ffa1017b2b7e6684369370372e3c5f9")

    # --- TV5: Retry mechanism preimage format ---
    # retry=0 is same as TV1
    # retry=1: preimage = seed || LE32(0) || LE32(1)
    preimage_retry1 = zero_seed + le32_bytes(0) + le32_bytes(1)
    h_retry1 = sha256(preimage_retry1)
    check("TV5 retry=1 SHA-256",
          bytes_to_hex(h_retry1),
          "4aefeea7a0bb3e887dfac5aba09fea61faaf95a48c1229186e9a671ed4738520")

    raw_retry1 = h_retry1[0] | (h_retry1[1] << 8) | (h_retry1[2] << 16) | (h_retry1[3] << 24)
    candidate_retry1 = raw_retry1 & 0x7FFFFFFF
    check("TV5 retry=1 candidate", candidate_retry1, 669970250)

    # retry=2: preimage = seed || LE32(0) || LE32(2)
    preimage_retry2 = zero_seed + le32_bytes(0) + le32_bytes(2)
    h_retry2 = sha256(preimage_retry2)
    check("TV5 retry=2 SHA-256",
          bytes_to_hex(h_retry2),
          "7d4b807e3471ee3bffc75392607322b2b9a7226132ff0301d8dce3243cfa03c8")

    raw_retry2 = h_retry2[0] | (h_retry2[1] << 8) | (h_retry2[2] << 16) | (h_retry2[3] << 24)
    candidate_retry2 = raw_retry2 & 0x7FFFFFFF
    check("TV5 retry=2 candidate", candidate_retry2, 2122337149)

    # --- TV6: FromSeed(seed=0x00..00, n=2) ---
    mat = from_seed(zero_seed, 2)
    check("TV6 matrix[0][0]", mat[0][0], 1432335981)
    check("TV6 matrix[0][1]", mat[0][1], 1134348657)
    check("TV6 matrix[1][0]", mat[1][0], 428617384)
    check("TV6 matrix[1][1]", mat[1][1], 258375063)

    # Also verify from_oracle(zero_seed, 2) and from_oracle(zero_seed, 3) directly
    check("TV6 from_oracle(zero_seed, 2)", from_oracle(zero_seed, 2), 428617384)
    check("TV6 from_oracle(zero_seed, 3)", from_oracle(zero_seed, 3), 258375063)

    # --- Noise derivation pinned vectors (section 8.2.2) ---
    sigma_zero = b'\x00' * 32

    tag_EL = derive_noise_seed('EL', sigma_zero)
    check("Noise tag_EL for sigma=0",
          bytes_to_hex(tag_EL),
          "993a427eeb3dc053000d570842d2e7f0f093393c00e8e729155c48719118b386")

    tag_ER = derive_noise_seed('ER', sigma_zero)
    check("Noise tag_ER for sigma=0",
          bytes_to_hex(tag_ER),
          "0b3b1aa329a9ee863b3aa0080346e4ced9842b39db47d70418af99120b6530a2")

    tag_FL = derive_noise_seed('FL', sigma_zero)
    check("Noise tag_FL for sigma=0",
          bytes_to_hex(tag_FL),
          "73ff6f6817e0c7e7ce9219076b14f1d932be70c641393bfc4c53a230bf65ddd8")

    tag_FR = derive_noise_seed('FR', sigma_zero)
    check("Noise tag_FR for sigma=0",
          bytes_to_hex(tag_FR),
          "91d399ff912ea452af750501448661096d5251cd17921403ab70d0c4561b45a3")

    # E_L pinned elements (n=4, r=2, sigma=0x00..00)
    noise = generate_noise(sigma_zero, 4, 2)

    check("Noise EL[0][0]", noise['EL'][0][0], 1931902215)
    check("Noise EL[0][1]", noise['EL'][0][1], 129748845)
    check("Noise EL[1][0]", noise['EL'][1][0], 505403935)
    check("Noise EL[1][1]", noise['EL'][1][1], 538008036)
    check("Noise EL[2][0]", noise['EL'][2][0], 1006343602)
    check("Noise EL[2][1]", noise['EL'][2][1], 1697202758)
    check("Noise EL[3][0]", noise['EL'][3][0], 2128262120)
    check("Noise EL[3][1]", noise['EL'][3][1], 942473671)

    # E_R pinned elements
    check("Noise ER[0][0]", noise['ER'][0][0], 962405871)
    check("Noise ER[0][1]", noise['ER'][0][1], 1142251768)
    check("Noise ER[0][2]", noise['ER'][0][2], 505582893)
    check("Noise ER[0][3]", noise['ER'][0][3], 443901062)
    check("Noise ER[1][0]", noise['ER'][1][0], 858057583)
    check("Noise ER[1][1]", noise['ER'][1][1], 2082571321)
    check("Noise ER[1][2]", noise['ER'][1][2], 70698889)
    check("Noise ER[1][3]", noise['ER'][1][3], 1087797252)

    # Domain separation: first element of each factor differs
    check("Noise FL[0][0]", from_oracle(noise['tag_FL'], 0), 1766706109)
    check("Noise FR[0][0]", from_oracle(noise['tag_FR'], 0), 1500561682)

    # --- reduce64 edge cases from spec section 7.3 ---
    check("reduce64(0)", reduce64(0), 0)
    check("reduce64(1)", reduce64(1), 1)
    check("reduce64(M31)", reduce64(M31), 0)
    check("reduce64(M31+1)", reduce64(M31 + 1), 1)
    check("reduce64(M31*M31)", reduce64(M31 * M31), 0)
    check("reduce64((M31-1)*(M31-1))", reduce64((M31 - 1) * (M31 - 1)), 1)

    # Single-fold boundary tests
    check("reduce64(2^62 - 1)", reduce64((1 << 62) - 1), ((1 << 62) - 1) % M31)
    check("reduce64(2^62)", reduce64(1 << 62), (1 << 62) % M31)
    check("reduce64((M31-1)*M31)", reduce64((M31 - 1) * M31), 0)

    # Double-fold required tests
    check("reduce64(2^63)", reduce64(1 << 63), 2)
    check("reduce64(2^63 - 1)", reduce64((1 << 63) - 1), 1)
    check("reduce64(2*(M31-1)^2)", reduce64(2 * (M31 - 1) * (M31 - 1)), 2)
    check("reduce64(UINT64_MAX)", reduce64((1 << 64) - 1), 3)
    check("reduce64(3*(M31-1)^2)", reduce64(3 * (M31 - 1) * (M31 - 1)), 3)
    check("reduce64(2^64 - M31)", reduce64((1 << 64) - M31), 4)

    # Power of two exhaustive check
    for k in range(64):
        x = 1 << k
        expected = 1 << (k % 31)
        actual = reduce64(x)
        check(f"reduce64(2^{k})", actual, expected)

    # --- dot product tests from spec section 7.3 ---
    check("dot([1,2,3,4],[5,6,7,8],4)", dot([1, 2, 3, 4], [5, 6, 7, 8], 4), 70)
    check("dot([],[],0)", dot([], [], 0), 0)

    # Worst case: all elements are M31-1
    a_max = [M31 - 1] * 100
    b_max = [M31 - 1] * 100
    check("dot(all-max, all-max, 100)", dot(a_max, b_max, 100), 100)

    a_max_512 = [M31 - 1] * 512
    b_max_512 = [M31 - 1] * 512
    check("dot(all-max, all-max, 512)", dot(a_max_512, b_max_512, 512), 512)

    return passes, fails, messages


# ---------------------------------------------------------------------------
# Generate additional test vectors
# ---------------------------------------------------------------------------

def generate_additional_vectors():
    """Generate additional test vectors beyond the spec's pinned ones."""
    vectors = {}

    zero_seed = b'\x00' * 32
    test_seed = sha256(b"test_seed")
    sigma_zero = b'\x00' * 32

    # ---------------------------------------------------------------
    # 1. from_oracle with 10 extra (seed, index) pairs
    # ---------------------------------------------------------------
    from_oracle_extra = []
    extra_pairs = [
        (zero_seed, 100),
        (zero_seed, 255),
        (zero_seed, 1000),
        (zero_seed, 65535),
        (zero_seed, 0xFFFFFFFF),
        (test_seed, 0),
        (test_seed, 1),
        (test_seed, 100),
        (test_seed, 999),
        (sha256(b"another_seed"), 12345),
    ]
    for seed, idx in extra_pairs:
        val = from_oracle(seed, idx)
        from_oracle_extra.append({
            "seed_hex": bytes_to_hex(seed),
            "index": idx,
            "result": val,
        })
    vectors["from_oracle_extra"] = from_oracle_extra

    # ---------------------------------------------------------------
    # 2. FromSeed for 4x4 and 8x8 matrices
    # ---------------------------------------------------------------
    mat_4x4 = from_seed(zero_seed, 4)
    vectors["from_seed_4x4"] = {
        "seed_hex": bytes_to_hex(zero_seed),
        "n": 4,
        "matrix": mat_4x4,
    }

    mat_8x8 = from_seed(zero_seed, 8)
    vectors["from_seed_8x8"] = {
        "seed_hex": bytes_to_hex(zero_seed),
        "n": 8,
        "matrix": mat_8x8,
    }

    # ---------------------------------------------------------------
    # 3. Noise generation for n=8, r=2
    # ---------------------------------------------------------------
    noise_8_2 = generate_noise(sigma_zero, 8, 2)
    vectors["noise_n8_r2"] = {
        "sigma_hex": bytes_to_hex(sigma_zero),
        "n": 8,
        "r": 2,
        "tag_EL_hex": bytes_to_hex(noise_8_2['tag_EL']),
        "tag_ER_hex": bytes_to_hex(noise_8_2['tag_ER']),
        "tag_FL_hex": bytes_to_hex(noise_8_2['tag_FL']),
        "tag_FR_hex": bytes_to_hex(noise_8_2['tag_FR']),
        "EL": noise_8_2['EL'],
        "ER": noise_8_2['ER'],
        "FL": noise_8_2['FL'],
        "FR": noise_8_2['FR'],
    }

    # ---------------------------------------------------------------
    # 4. Compression vector for b=8 and b=16
    # ---------------------------------------------------------------
    cv_b8 = derive_compression_vector(sigma_zero, 8)
    cv_seed_b8 = sha256(COMPRESS_TAG + sigma_zero)
    vectors["compression_vector_b8"] = {
        "sigma_hex": bytes_to_hex(sigma_zero),
        "b": 8,
        "compress_seed_hex": bytes_to_hex(cv_seed_b8),
        "vector_length": len(cv_b8),
        "vector": cv_b8,
    }

    cv_b16 = derive_compression_vector(sigma_zero, 16)
    cv_seed_b16 = sha256(COMPRESS_TAG + sigma_zero)
    vectors["compression_vector_b16"] = {
        "sigma_hex": bytes_to_hex(sigma_zero),
        "b": 16,
        "compress_seed_hex": bytes_to_hex(cv_seed_b16),
        "vector_length": len(cv_b16),
        "vector": cv_b16,
    }

    # ---------------------------------------------------------------
    # 5. Complete canonical matmul + transcript hash for n=8, b=4
    # ---------------------------------------------------------------
    # Use simple seeds for A' and B' to keep vectors tractable
    seed_a = sha256(b"seed_a_for_test")
    seed_b = sha256(b"seed_b_for_test")
    sigma_test = sha256(b"sigma_for_test")

    A_prime = from_seed(seed_a, 8)
    B_prime = from_seed(seed_b, 8)

    C_prime, z_hex = canonical_matmul(A_prime, B_prime, 4, sigma_test)

    vectors["canonical_matmul_n8_b4"] = {
        "seed_a_hex": bytes_to_hex(seed_a),
        "seed_b_hex": bytes_to_hex(seed_b),
        "sigma_hex": bytes_to_hex(sigma_test),
        "n": 8,
        "b": 4,
        "A_prime": A_prime,
        "B_prime": B_prime,
        "C_prime": C_prime,
        "transcript_hash_hex": z_hex,
        "num_intermediates": (8 // 4) ** 3,
    }

    # ---------------------------------------------------------------
    # 6. reduce64 edge cases
    # ---------------------------------------------------------------
    reduce64_cases = [
        {"input": 0, "input_desc": "0"},
        {"input": 1, "input_desc": "1"},
        {"input": M31, "input_desc": "M31"},
        {"input": M31 + 1, "input_desc": "M31+1"},
        {"input": 1 << 62, "input_desc": "2^62"},
        {"input": 1 << 63, "input_desc": "2^63"},
        {"input": (1 << 63) - 1, "input_desc": "2^63-1"},
        {"input": (1 << 64) - 1, "input_desc": "2^64-1"},
    ]
    for case in reduce64_cases:
        case["output"] = reduce64(case["input"])
        case["input_hex"] = hex(case["input"])
    vectors["reduce64_edge_cases"] = reduce64_cases

    # ---------------------------------------------------------------
    # 7. dot product of length 4 with all-max-value elements
    # ---------------------------------------------------------------
    a_max4 = [M31 - 1] * 4
    b_max4 = [M31 - 1] * 4
    vectors["dot_all_max_len4"] = {
        "a": a_max4,
        "b": b_max4,
        "length": 4,
        "result": dot(a_max4, b_max4, 4),
        "note": "Each (M31-1)^2 mod M31 = 1, so dot = 4",
    }

    # ---------------------------------------------------------------
    # Pinned spec test vectors (collected for completeness in JSON)
    # ---------------------------------------------------------------
    vectors["pinned_tv1"] = {
        "seed_hex": bytes_to_hex(zero_seed),
        "index": 0,
        "sha256_hex": "6db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e",
        "raw_le32": 0xd55fb66d,
        "masked": 0x555fb66d,
        "result": 1432335981,
    }
    vectors["pinned_tv2"] = {
        "seed_hex": bytes_to_hex(zero_seed),
        "index": 1,
        "sha256_hex": "71c99cc3bc21757feed5b712744ebb0f770d5c41d99189f9457495747bf11050",
        "result": 1134348657,
    }
    vectors["pinned_tv3"] = {
        "seed_hex": bytes_to_hex(zero_seed),
        "index": 7,
        "sha256_hex": "95f1f8ffe5b54fd46e622b34b93464acfc25fd54cabd50a3f0143479e4253b42",
        "result": 2147021205,
    }
    vectors["pinned_tv4"] = {
        "seed_hex": bytes_to_hex(test_seed),
        "index": 42,
        "sha256_hex": "6ecbbdccdae17aaac5acb50d7b23107f7ffa1017b2b7e6684369370372e3c5f9",
        "result": 1287506798,
    }
    vectors["pinned_tv5_retry"] = {
        "seed_hex": bytes_to_hex(zero_seed),
        "index": 0,
        "retry_0_sha256": "6db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e",
        "retry_0_candidate": 1432335981,
        "retry_1_sha256": "4aefeea7a0bb3e887dfac5aba09fea61faaf95a48c1229186e9a671ed4738520",
        "retry_1_candidate": 669970250,
        "retry_2_sha256": "7d4b807e3471ee3bffc75392607322b2b9a7226132ff0301d8dce3243cfa03c8",
        "retry_2_candidate": 2122337149,
    }
    vectors["pinned_tv6_from_seed_2x2"] = {
        "seed_hex": bytes_to_hex(zero_seed),
        "n": 2,
        "matrix": [
            [1432335981, 1134348657],
            [428617384, 258375063],
        ],
    }

    # Noise pinned vectors
    vectors["pinned_noise_seeds"] = {
        "sigma_hex": bytes_to_hex(sigma_zero),
        "tag_EL_hex": "993a427eeb3dc053000d570842d2e7f0f093393c00e8e729155c48719118b386",
        "tag_ER_hex": "0b3b1aa329a9ee863b3aa0080346e4ced9842b39db47d70418af99120b6530a2",
        "tag_FL_hex": "73ff6f6817e0c7e7ce9219076b14f1d932be70c641393bfc4c53a230bf65ddd8",
        "tag_FR_hex": "91d399ff912ea452af750501448661096d5251cd17921403ab70d0c4561b45a3",
    }
    vectors["pinned_noise_EL_n4_r2"] = {
        "sigma_hex": bytes_to_hex(sigma_zero),
        "n": 4,
        "r": 2,
        "matrix": [
            [1931902215, 129748845],
            [505403935, 538008036],
            [1006343602, 1697202758],
            [2128262120, 942473671],
        ],
    }
    vectors["pinned_noise_ER_n4_r2"] = {
        "sigma_hex": bytes_to_hex(sigma_zero),
        "n": 4,
        "r": 2,
        "matrix": [
            [962405871, 1142251768, 505582893, 443901062],
            [858057583, 2082571321, 70698889, 1087797252],
        ],
    }
    vectors["pinned_noise_domain_separation"] = {
        "sigma_hex": bytes_to_hex(sigma_zero),
        "first_elements": {
            "EL_0": 1931902215,
            "ER_0": 962405871,
            "FL_0": 1766706109,
            "FR_0": 1500561682,
        },
    }

    return vectors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("BTX MatMul PoW Reference Implementation -- Test Vector Generator")
    print("=" * 70)
    print()

    # Step 1: Verify all pinned test vectors from the spec
    print("Verifying pinned test vectors from the spec...")
    print("-" * 50)
    passes, fails, messages = verify_pinned_vectors()
    for msg in messages:
        print(msg)
    print("-" * 50)
    print(f"Pinned vector verification: {passes} passed, {fails} failed")
    print()

    if fails > 0:
        print("FATAL: Pinned test vectors do not match spec. Aborting.")
        sys.exit(1)

    # Step 2: Generate additional test vectors
    print("Generating additional test vectors...")
    vectors = generate_additional_vectors()

    # Step 3: Write JSON
    output_path = "/home/user/btx-node/test/reference/test_vectors.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(vectors, f, indent=2)
    print(f"Test vectors written to: {output_path}")
    print()

    # Summary of what was generated
    print("Generated test vector sections:")
    for key in vectors:
        val = vectors[key]
        if isinstance(val, list):
            print(f"  {key}: {len(val)} entries")
        elif isinstance(val, dict):
            keys_str = ", ".join(sorted(val.keys())[:5])
            if len(val.keys()) > 5:
                keys_str += ", ..."
            print(f"  {key}: dict with keys [{keys_str}]")
        else:
            print(f"  {key}: {type(val).__name__}")

    print()
    print(f"Total pinned vectors verified: {passes}")
    print(f"All checks passed: {'YES' if fails == 0 else 'NO'}")
    print()

    if fails == 0:
        print("SUCCESS: All pinned test vectors match the spec.")
        print("SUCCESS: Additional test vectors generated.")
        sys.exit(0)
    else:
        print(f"FAILURE: {fails} pinned test vectors did not match.")
        sys.exit(1)


if __name__ == '__main__':
    main()
