#!/usr/bin/env python3
# Copyright (c) 2026 The BTX Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Toy-n C-15 attack harness (stdlib only).

Builds a synthetic low-rank B32 = (G·W)·H (or random full-rank noise),
runs normative Extract, fits best affine / degree-2 surrogates of Bhat from
B32, reports R², and checks a Freivalds-style residual on a random probe.

Expected outcome for honest MatExpand + ChaCha Extract:
  - affine / degree-2 R² far below 1 (collapse rejected)
  - Freivalds residual on an affine-surrogate Bhat is typically nonzero

This does NOT close C-15; it is a build-free reproducibility aid for
external cryptanalysts. See README.md and the external C-15 packet.
"""

from __future__ import annotations

import argparse
import math
import random
import sys
from pathlib import Path

from reference_extract import (
    derive_matexpand_prf_key,
    extract_dequant_matexpand,
    load_vectors,
)


def matmul_i8_i8(A: list[list[int]], B: list[list[int]]) -> list[list[int]]:
    n, k = len(A), len(A[0])
    m = len(B[0])
    assert len(B) == k
    out = [[0] * m for _ in range(n)]
    for i in range(n):
        for t in range(k):
            a = A[i][t]
            if a == 0:
                continue
            brow = B[t]
            orow = out[i]
            for j in range(m):
                orow[j] += a * brow[j]
    return out


def matmul_i32_i8(A: list[list[int]], B: list[list[int]]) -> list[list[int]]:
    n, k = len(A), len(A[0])
    m = len(B[0])
    assert len(B) == k
    out = [[0] * m for _ in range(n)]
    for i in range(n):
        for t in range(k):
            a = A[i][t]
            if a == 0:
                continue
            brow = B[t]
            orow = out[i]
            for j in range(m):
                orow[j] += a * brow[j]
    return out


def rand_m11(rng: random.Random) -> int:
    return rng.choice([0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6])


def synthetic_matexpand_b32(n: int, w: int, rng: random.Random) -> list[list[int]]:
    """Tiny MatExpand panels with M11-ish entries; B32 = (G·W)·H, rank ≤ w."""
    G = [[rand_m11(rng) for _ in range(n)] for _ in range(n)]
    W = [[rand_m11(rng) for _ in range(w)] for _ in range(n)]
    H = [[rand_m11(rng) for _ in range(n)] for _ in range(w)]
    Y = matmul_i8_i8(G, W)
    return matmul_i32_i8(Y, H)


def matrix_rank_mod(M: list[list[int]], modulus: int = 2_147_483_647) -> int:
    """Gaussian elimination rank over a large prime (spectral sanity check)."""
    a = [row[:] for row in M]
    rows, cols = len(a), len(a[0])
    r = 0
    for c in range(cols):
        pivot = None
        for i in range(r, rows):
            if a[i][c] % modulus != 0:
                pivot = i
                break
        if pivot is None:
            continue
        a[r], a[pivot] = a[pivot], a[r]
        piv = a[r][c] % modulus
        inv = pow(piv, -1, modulus)
        for j in range(c, cols):
            a[r][j] = (a[r][j] * inv) % modulus
        for i in range(rows):
            if i == r:
                continue
            factor = a[i][c] % modulus
            if factor == 0:
                continue
            for j in range(c, cols):
                a[i][j] = (a[i][j] - factor * a[r][j]) % modulus
        r += 1
        if r == rows:
            break
    return r


def extract_matrix(B32: list[list[int]], prf_key: bytes) -> list[list[int]]:
    n = len(B32)
    return [
        [extract_dequant_matexpand(B32[i][j], i, j, prf_key) for j in range(n)]
        for i in range(n)
    ]


def _fit_poly(xs: list[float], ys: list[float], degree: int) -> tuple[list[float], float]:
    """Ordinary least squares poly fit via normal equations (no numpy)."""
    m = degree + 1
    # Build design matrix columns 1, x, x^2, ...
    xtx = [[0.0] * m for _ in range(m)]
    xty = [0.0] * m
    for x, y in zip(xs, ys):
        powers = [1.0]
        for _ in range(degree):
            powers.append(powers[-1] * x)
        for a in range(m):
            xty[a] += powers[a] * y
            for b in range(m):
                xtx[a][b] += powers[a] * powers[b]
    # Solve xtx β = xty (Gaussian elimination)
    aug = [xtx[i][:] + [xty[i]] for i in range(m)]
    for col in range(m):
        piv = max(range(col, m), key=lambda r: abs(aug[r][col]))
        if abs(aug[piv][col]) < 1e-18:
            return [0.0] * m, float("nan")
        aug[col], aug[piv] = aug[piv], aug[col]
        scale = aug[col][col]
        for j in range(col, m + 1):
            aug[col][j] /= scale
        for r in range(m):
            if r == col:
                continue
            factor = aug[r][col]
            for j in range(col, m + 1):
                aug[r][j] -= factor * aug[col][j]
    beta = [aug[i][m] for i in range(m)]

    y_mean = sum(ys) / len(ys)
    ss_tot = sum((y - y_mean) ** 2 for y in ys)
    ss_res = 0.0
    for x, y in zip(xs, ys):
        pred = 0.0
        p = 1.0
        for b in beta:
            pred += b * p
            p *= x
        ss_res += (y - pred) ** 2
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot > 1e-18 else float("nan")
    return beta, r2


def freivalds_residual(
    Bhat: list[list[int]], Bhat_hat: list[list[int]], rng: random.Random
) -> int:
    """
    Freivalds-style probe: r^T (Bhat - Bhat') s for random ±1 vectors.
    Nonzero ⇒ surrogate matrix is not equal to Extract output (expected).
    """
    n = len(Bhat)
    r = [rng.choice((-1, 1)) for _ in range(n)]
    s = [rng.choice((-1, 1)) for _ in range(n)]
    # t = (Bhat - Bhat') s
    t = [0] * n
    for i in range(n):
        acc = 0
        for j in range(n):
            acc += (Bhat[i][j] - Bhat_hat[i][j]) * s[j]
        t[i] = acc
    return sum(r[i] * t[i] for i in range(n))


def apply_surrogate(B32: list[list[int]], beta: list[float]) -> list[list[int]]:
    n = len(B32)
    out = [[0] * n for _ in range(n)]
    degree = len(beta) - 1
    for i in range(n):
        for j in range(n):
            x = float(B32[i][j])
            pred = 0.0
            p = 1.0
            for b in beta:
                pred += b * p
                p *= x
            # Round to nearest int8-ish for residual check
            out[i][j] = int(round(pred))
    return out


def run(n: int = 8, w: int = 4, seed: int = 1) -> int:
    vectors = load_vectors()
    prf_key = derive_matexpand_prf_key(vectors["seed_w_hex"])
    rng = random.Random(seed)

    B32 = synthetic_matexpand_b32(n, w, rng)
    rank = matrix_rank_mod(B32)
    print(f"toy MatExpand: n={n} w={w} rank(B32)={rank} (expect ≤ w={w})")
    if rank > w:
        print("WARN: synthetic rank exceeded w (should not happen for (G W) H)")

    Bhat = extract_matrix(B32, prf_key)

    xs: list[float] = []
    ys: list[float] = []
    for i in range(n):
        for j in range(n):
            xs.append(float(B32[i][j]))
            ys.append(float(Bhat[i][j]))

    beta1, r2_affine = _fit_poly(xs, ys, degree=1)
    beta2, r2_deg2 = _fit_poly(xs, ys, degree=2)

    Bhat_aff = apply_surrogate(B32, beta1)
    residual = freivalds_residual(Bhat, Bhat_aff, rng)

    print(f"affine fit β={beta1}  R²={r2_affine:.6f}")
    print(f"degree-2 fit β={beta2}  R²={r2_deg2:.6f}")
    print(f"Freivalds-style residual rᵀ(B̂−B̂')s = {residual}  (nonzero expected)")
    print()
    print(
        "Interpretation: rejection of affine/low-degree collapse is EXPECTED for "
        "ChaCha20-PRF Extract. High R² or a zero residual on dense samples would "
        "be a C-15 finding — report it. C-15 remains OPEN (not closed by this toy)."
    )

    # Soft expectations for CI-ish smoke: R² should not look like a perfect fit.
    if math.isnan(r2_affine) or math.isnan(r2_deg2):
        print("FAIL: degenerate fit")
        return 1
    if r2_affine > 0.95 or r2_deg2 > 0.98:
        print("FAIL: unexpectedly high surrogate R² (investigate C-15)")
        return 1
    if residual == 0 and n >= 4:
        # Possible but rare on tiny n; warn rather than hard-fail.
        print("WARN: Freivalds residual was zero — rerun with larger n/seed")
    print("PASS (toy harness smoke)")
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--n", type=int, default=8, help="toy matrix dimension")
    p.add_argument("--w", type=int, default=4, help="toy panel width (rank bound)")
    p.add_argument("--seed", type=int, default=1, help="RNG seed")
    args = p.parse_args(argv[1:])
    if args.w > args.n:
        print("w should be ≤ n for a meaningful low-rank toy", file=sys.stderr)
    return run(n=args.n, w=args.w, seed=args.seed)


if __name__ == "__main__":
    # Allow running from any cwd by putting this directory on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main(sys.argv))
