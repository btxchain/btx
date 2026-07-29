#!/usr/bin/env python3
# Copyright (c) 2026 The BTX Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Standalone Lever-B MX-block MatExpand Extract (ENC_BMX4C_LT).

Matches src/matmul/matmul_v4_lt.cpp::ExtractDequantMatExpand /
DeriveMatExpandPrfKey / DeriveMatExpandMxScale /
ExtractMatExpandMxTileMantissas bit-for-bit.

Legacy ChaChaCell Extract (related-nonce differentials) is available as
extract_dequant_matexpand_chacha_cell + derive_matexpand_prf_key_chacha_cell.

No bitcoind / node build required. Stdlib only.

Bitcoin uint256 endianness: FromHex/GetHex display is byte-reversed vs
bytes.fromhex(); SHA256(tag || seed_w) hashes the little-endian memory bytes.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

MX_PRF_TAG = b"BTX_MATEXPAND_MXPRF_V44LT"
MX_SCALE_TAG = b"BTX_MATEXPAND_MXSCALE_V44LT"
CELL_PRF_TAG = b"BTX_MATEXPAND_PRF_V44LT"
LANE_MANT = 0x4D414E54  # 'MANT'
LANE_SCALE = 0x53434C45  # 'SCLE'
LANE_MXBL = 0x4D58424C  # 'MXBL'
BLOCK_LEN = 32

# E2M1 → M11 rejection (SampleMantissaNibble). Rejected nibbles: 1,3,8,9,11.
_M11_ACCEPTED = [False] * 16
_M11_VALUE = [0] * 16
for _nib in range(16):
    _sign = (_nib >> 3) & 1
    _exp = (_nib >> 1) & 3
    _man = _nib & 1
    _mag = 0
    _integer = True
    if _exp == 0:
        _mag = 0
        _integer = _man == 0
    elif _exp == 1:
        _mag = 1
        _integer = _man == 0
    elif _exp == 2:
        _mag = 2 if _man == 0 else 3
    else:
        _mag = 4 if _man == 0 else 6
    if not _integer or (_sign and _mag == 0):
        continue
    _M11_ACCEPTED[_nib] = True
    _M11_VALUE[_nib] = -_mag if _sign else _mag


def uint256_bytes_from_hex(hex_str: str) -> bytes:
    """Bitcoin uint256::FromHex → 32 little-endian memory bytes."""
    h = hex_str.strip().lower()
    if h.startswith("0x"):
        h = h[2:]
    raw = bytes.fromhex(h)
    if len(raw) != 32:
        raise ValueError(f"uint256 hex must be 32 bytes, got {len(raw)}")
    return raw[::-1]


def derive_matexpand_prf_key(seed_w_hex: str) -> bytes:
    """prf_key = SHA256(\"BTX_MATEXPAND_MXPRF_V44LT\" ‖ seed_w_le)."""
    return hashlib.sha256(MX_PRF_TAG + uint256_bytes_from_hex(seed_w_hex)).digest()


def derive_matexpand_prf_key_chacha_cell(seed_w_hex: str) -> bytes:
    """Legacy cell key = SHA256(\"BTX_MATEXPAND_PRF_V44LT\" ‖ seed_w_le)."""
    return hashlib.sha256(CELL_PRF_TAG + uint256_bytes_from_hex(seed_w_hex)).digest()


def _rotl32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _quarter(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


def chacha20_block_words(key32: bytes, counter: int, nonce_first: int, nonce_second: int) -> list[int]:
    """One RFC8439 ChaCha20 block as 16 LE words (crypto/chacha20.h layout)."""
    if len(key32) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    k = [struct.unpack_from("<I", key32, 4 * i)[0] for i in range(8)]
    x = [
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
        k[0],
        k[1],
        k[2],
        k[3],
        k[4],
        k[5],
        k[6],
        k[7],
        counter & 0xFFFFFFFF,
        nonce_first & 0xFFFFFFFF,
        nonce_second & 0xFFFFFFFF,
        (nonce_second >> 32) & 0xFFFFFFFF,
    ]
    j = x[:]
    for _ in range(10):
        _quarter(x, 0, 4, 8, 12)
        _quarter(x, 1, 5, 9, 13)
        _quarter(x, 2, 6, 10, 14)
        _quarter(x, 3, 7, 11, 15)
        _quarter(x, 0, 5, 10, 15)
        _quarter(x, 1, 6, 11, 12)
        _quarter(x, 2, 7, 8, 13)
        _quarter(x, 3, 4, 9, 14)
    return [(x[i] + j[i]) & 0xFFFFFFFF for i in range(16)]


def chacha20_block_bytes(key32: bytes, counter: int, nonce_first: int, nonce_second: int) -> bytes:
    words = chacha20_block_words(key32, counter, nonce_first, nonce_second)
    return b"".join(struct.pack("<I", w) for w in words)


def matexpand_prf_le64(prf_key: bytes, raw: int, i: int, j: int, remix: int, lane: int) -> int:
    """Legacy AccelReplicaMatExpandPrfLE64 / first 8 bytes of cell keystream."""
    nonce_first = (raw & 0xFFFFFFFF) ^ (lane & 0xFFFFFFFF)
    nonce_second = ((i & 0xFFFFFFFF) << 32) | (j & 0xFFFFFFFF)
    words = chacha20_block_words(prf_key, remix, nonce_first, nonce_second)
    return words[0] | (words[1] << 32)


def sample_mantissa_nibble(nibble: int) -> tuple[bool, int]:
    n = nibble & 0x0F
    return _M11_ACCEPTED[n], _M11_VALUE[n]


def derive_matexpand_mx_scale(prf_key: bytes, i: int, bj: int) -> int:
    """e = SHA256(MXSCALE ‖ prf_key ‖ LE32(i) ‖ LE32(bj))[0] & 3."""
    digest = hashlib.sha256(
        MX_SCALE_TAG + prf_key + struct.pack("<I", i & 0xFFFFFFFF) + struct.pack("<I", bj & 0xFFFFFFFF)
    ).digest()
    return digest[0] & 0x3


def extract_mat_expand_mx_tile_mantissas(
    prf_key: bytes, i: int, bj: int, raw32: list[int]
) -> list[int]:
    """32 M11 mantissas for tile (i, bj); raw32 length must be 32."""
    if len(raw32) != BLOCK_LEN:
        raise ValueError("raw32 must have length 32")
    mu_out = [0] * BLOCK_LEN
    filled = 0
    remix = 0
    while filled < BLOCK_LEN:
        ks = chacha20_block_bytes(
            prf_key, remix, (bj ^ LANE_MXBL) & 0xFFFFFFFF, ((i & 0xFFFFFFFF) << 32) | (bj & 0xFFFFFFFF)
        )
        for byte in ks:
            if filled >= BLOCK_LEN:
                break
            for shift in (0, 4):
                if filled >= BLOCK_LEN:
                    break
                nibble = (byte >> shift) & 0x0F
                raw_u = raw32[filled] & 0xFFFFFFFF
                mixed = (nibble ^ (((raw_u * 0x9E3779B9) & 0xFFFFFFFF) >> 28)) & 0x0F
                accepted, mu = sample_mantissa_nibble(mixed)
                if accepted:
                    mu_out[filled] = mu
                    filled += 1
        remix += 1
    return mu_out


def extract_dequant_matexpand_tile(
    raw32: list[int], i: int, bj: int, prf_key: bytes
) -> list[int]:
    """Consensus-faithful dequantization of one real 32-value B32 tile."""
    mu = extract_mat_expand_mx_tile_mantissas(prf_key, i, bj, raw32)
    scale = 1 << derive_matexpand_mx_scale(prf_key, i, bj)
    return [int(v) * scale for v in mu]


def extract_dequant_matexpand_matrix(B32: list[list[int]], prf_key: bytes) -> list[list[int]]:
    """Consensus-faithful MX Extract over a square B32 matrix.

    Consensus MatExpand consumes complete 32-column tiles.  Refuse partial
    tiles so reviewer probes cannot silently fall back to synthetic repeated
    raw values.
    """
    if not B32 or not B32[0]:
        raise ValueError("B32 must be a non-empty square matrix")
    n = len(B32)
    if any(len(row) != n for row in B32):
        raise ValueError("B32 must be square")
    if n % BLOCK_LEN != 0:
        raise ValueError(f"B32 dimension must be a multiple of {BLOCK_LEN}, got {n}")

    out = [[0] * n for _ in range(n)]
    for i, row in enumerate(B32):
        for start in range(0, n, BLOCK_LEN):
            bj = start // BLOCK_LEN
            out[i][start : start + BLOCK_LEN] = extract_dequant_matexpand_tile(
                row[start : start + BLOCK_LEN], i, bj, prf_key
            )
    return out


def extract_dequant_matexpand(raw: int, i: int, j: int, prf_key: bytes) -> int:
    """Synthetic repeated-raw tile convenience; not consensus-faithful.

    Retained for frozen differential vectors only.  Reviewer attacks over B32
    must use extract_dequant_matexpand_tile/matrix so all 32 real values affect
    rejection-sampling alignment exactly as in MatExpandCore.
    """
    bj = j // BLOCK_LEN
    t = j % BLOCK_LEN
    raw32 = [raw] * BLOCK_LEN
    mu = extract_mat_expand_mx_tile_mantissas(prf_key, i, bj, raw32)
    e = derive_matexpand_mx_scale(prf_key, i, bj)
    return int(mu[t]) * (1 << e)


def extract_dequant_matexpand_chacha_cell(raw: int, i: int, j: int, prf_key: bytes) -> int:
    """Legacy per-cell ChaCha Extract (related-nonce / differential tests only)."""
    remix = 0
    while True:
        mixed = matexpand_prf_le64(prf_key, raw, i, j, remix, LANE_MANT)
        for shift in range(0, 64, 4):
            accepted, mu = sample_mantissa_nibble((mixed >> shift) & 0x0F)
            if not accepted:
                continue
            scale_stream = matexpand_prf_le64(prf_key, raw, i, j, remix, LANE_SCALE)
            e = scale_stream & 0x3
            return int(mu) * (1 << e)
        remix += 1


def load_vectors(path: Path | None = None) -> dict:
    if path is None:
        path = Path(__file__).with_name("test-vectors.json")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _i32(u: int) -> int:
    u &= 0xFFFFFFFF
    return u - 0x100000000 if u >= 0x80000000 else u


def verify_related_nonce_pack(v: dict, cell_prf_key: bytes) -> bool:
    """Wave-3 Gap#5: ≥32 Mant/Scale XOR-identity tuples + B32 Δ negative control.
    Uses legacy ChaChaCell key/lanes (demoted under MX Extract)."""
    import random

    rn = v.get("related_nonce_lane_xor")
    if not rn:
        print("FAIL related_nonce_lane_xor section missing")
        return False
    ok = True
    delta = int(rn["delta"])
    if delta != (LANE_MANT ^ LANE_SCALE):
        print(f"FAIL related-nonce Δ: got {delta:#x} expected {LANE_MANT ^ LANE_SCALE:#x}")
        ok = False
    tuples = rn.get("tuples") or []
    if len(tuples) < 32:
        print(f"FAIL related-nonce tuples: need ≥32, got {len(tuples)}")
        ok = False
    for t in tuples:
        raw, i, j, remix = t["raw"], t["i"], t["j"], t["remix"]
        mant = matexpand_prf_le64(cell_prf_key, raw, i, j, remix, LANE_MANT)
        scale = matexpand_prf_le64(cell_prf_key, raw, i, j, remix, LANE_SCALE)
        raw_rel = _i32((raw & 0xFFFFFFFF) ^ delta)
        mant_rel = matexpand_prf_le64(cell_prf_key, raw_rel, i, j, remix, LANE_MANT)
        scale_rel = matexpand_prf_le64(cell_prf_key, raw_rel, i, j, remix, LANE_SCALE)
        if mant != scale_rel or scale != mant_rel:
            print(f"FAIL identity raw={raw} i={i} j={j} remix={remix}")
            ok = False
        if (
            mant != t["mant_le64"]
            or scale != t["scale_le64"]
            or mant_rel != t["mant_at_raw_xor_delta"]
            or scale_rel != t["scale_at_raw_xor_delta"]
        ):
            print(f"FAIL pinned LE64 raw={raw} i={i} j={j} remix={remix}")
            ok = False

    nc = rn.get("b32_delta_collision_negative_control") or {}
    grid = nc.get("grid") or {}
    n, w, seed = int(grid.get("n", 0)), int(grid.get("w", 0)), int(grid.get("seed", 0))
    if n < 2 or w < 1:
        print("FAIL B32 Δ-collision grid missing")
        return False

    def rand_m11(rng: random.Random) -> int:
        return rng.choice([0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6])

    def mm_i8(A: list[list[int]], B: list[list[int]]) -> list[list[int]]:
        nn, kk, mm = len(A), len(A[0]), len(B[0])
        return [
            [sum(int(A[r][t]) * int(B[t][c]) for t in range(kk)) for c in range(mm)]
            for r in range(nn)
        ]

    def mm_i32(A: list[list[int]], B: list[list[int]]) -> list[list[int]]:
        nn, kk, mm = len(A), len(A[0]), len(B[0])
        return [
            [sum(int(A[r][t]) * int(B[t][c]) for t in range(kk)) for c in range(mm)]
            for r in range(nn)
        ]

    rng = random.Random(seed)
    G = [[rand_m11(rng) for _ in range(n)] for _ in range(n)]
    W = [[rand_m11(rng) for _ in range(w)] for _ in range(n)]
    H = [[rand_m11(rng) for _ in range(n)] for _ in range(w)]
    B32 = mm_i32(mm_i8(G, W), H)
    flat = [B32[r][c] & 0xFFFFFFFF for r in range(n) for c in range(n)]
    cells = len(flat)
    pairs = cells * (cells - 1) // 2

    def count_xor(delta_u: int) -> int:
        d = delta_u & 0xFFFFFFFF
        c = 0
        for a in range(cells):
            for b in range(a + 1, cells):
                if (flat[a] ^ flat[b]) == d:
                    c += 1
        return c

    got_delta = count_xor(delta)
    if got_delta != int(nc.get("delta_collision_count", -1)):
        print(
            f"FAIL B32 Δ-collisions: got {got_delta} expected {nc.get('delta_collision_count')}"
        )
        ok = False
    if got_delta > 1:
        print(f"FAIL B32 Δ-graph denser than chance bound: count={got_delta}")
        ok = False
    if cells != int(nc.get("cells", -1)) or pairs != int(nc.get("unordered_pairs", -1)):
        print("FAIL B32 Δ-collision metadata cells/pairs mismatch")
        ok = False
    return ok


def verify_goldens(vectors: dict | None = None) -> int:
    """Return 0 on PASS, 1 on FAIL. Prints PASS/FAIL."""
    v = vectors if vectors is not None else load_vectors()
    seed_w = v["seed_w_hex"]
    prf_key = derive_matexpand_prf_key(seed_w)
    expected_key = bytes.fromhex(v["prf_key_hex"])
    ok = True
    if prf_key != expected_key:
        print(f"FAIL prf_key: got {prf_key.hex()} expected {v['prf_key_hex']}")
        ok = False

    for case in v["extract_goldens"]:
        got = extract_dequant_matexpand(case["raw"], case["i"], case["j"], prf_key)
        exp = case["expected"]
        if got != exp:
            print(
                f"FAIL extract raw={case['raw']} i={case['i']} j={case['j']}: "
                f"got={got} expected={exp}"
            )
            ok = False
        if got < -48 or got > 48:
            print(f"FAIL range raw={case['raw']}: got={got} outside [-48,48]")
            ok = False

    for case in v.get("mx_real_tile_goldens", []):
        raw32 = case["raw32"]
        i, bj = case["i"], case["bj"]
        got_mu = extract_mat_expand_mx_tile_mantissas(prf_key, i, bj, raw32)
        got_e = derive_matexpand_mx_scale(prf_key, i, bj)
        got = extract_dequant_matexpand_tile(raw32, i, bj, prf_key)
        if got_mu != case["expected_mantissas"]:
            print(f"FAIL real MX tile mantissas i={i} bj={bj}: got={got_mu}")
            ok = False
        if got_e != case["expected_scale_e"]:
            print(f"FAIL real MX tile scale i={i} bj={bj}: got={got_e}")
            ok = False
        if got != case["expected_dequant"]:
            print(f"FAIL real MX tile dequant i={i} bj={bj}: got={got}")
            ok = False
        if any(vv < -48 or vv > 48 for vv in got):
            print(f"FAIL real MX tile range i={i} bj={bj}: got={got}")
            ok = False

    # AccelReplica parity: same Python path is the AccelReplica twin.
    for case in v.get("accel_replica_parity", {}).get("cases", []):
        raw, i, j = case["raw"], case["i"], case["j"]
        got = extract_dequant_matexpand(raw, i, j, prf_key)
        if "expected" in case:
            if got != case["expected"]:
                print(f"FAIL accel parity raw={raw} i={i} j={j}: got={got}")
                ok = False
        if got < -48 or got > 48:
            print(f"FAIL accel range raw={raw}: got={got}")
            ok = False

    cell_key = derive_matexpand_prf_key_chacha_cell(seed_w)
    if "chacha_cell_prf_key_hex" in v and cell_key != bytes.fromhex(v["chacha_cell_prf_key_hex"]):
        print(
            f"FAIL cell_prf_key: got {cell_key.hex()} expected {v['chacha_cell_prf_key_hex']}"
        )
        ok = False
    for case in v.get("chacha_cell_extract_goldens", []):
        got = extract_dequant_matexpand_chacha_cell(case["raw"], case["i"], case["j"], cell_key)
        if got != case["expected"]:
            print(
                f"FAIL cell extract raw={case['raw']} i={case['i']} j={case['j']}: "
                f"got={got} expected={case['expected']}"
            )
            ok = False

    if not verify_related_nonce_pack(v, cell_key):
        ok = False

    if ok:
        print("PASS")
        return 0
    print("FAIL")
    return 1


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else None
    return verify_goldens(load_vectors(path) if path else None)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
