#!/usr/bin/env python3
# Copyright (c) 2026 The BTX Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Spectral / approx-B̂ probe for C-15 Gap #6 (stdlib only).

For each toy n ∈ {8, 16, 32}:
  1) Build synthetic low-rank B32 = (G·W)·H (rank ≤ w).
  2) Run normative ChaCha20-PRF Extract → B̂.
  3) SVD-style spectrum of B̂ (power iteration + deflation).
  4) CCA-style: cos(θ_min) between col(B32) and top-w left singular subspace of B̂.
  5) Structured approx: project B̂ onto the row/col spaces of B32; measure
     Frobenius residual and Freivalds-style residual vs true Extract output.

Expected honest outcome: B̂ is *not* well-approximated by B32's thin spaces
(energy not concentrated in top-w; CCA ≪ 1; Freivalds residual typically
nonzero). That is empirical support only.

IMPORTANT — empirics alone do NOT claim §0.1 FAIL and do NOT close C-15.
A firm FAIL requires a concrete win against packet §0.1 cost thresholds.
See spectral_approx_probe.md.
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
from toy_attack_harness import (
    freivalds_residual,
    matrix_rank_mod,
    synthetic_matexpand_b32,
)


DEFAULT_NS = (8, 16, 32)


def extract_matrix(B32: list[list[int]], prf_key: bytes) -> list[list[int]]:
    n = len(B32)
    return [
        [extract_dequant_matexpand(B32[i][j], i, j, prf_key) for j in range(n)]
        for i in range(n)
    ]


def to_float(M: list[list[int]]) -> list[list[float]]:
    return [[float(x) for x in row] for row in M]


def mat_t(M: list[list[float]]) -> list[list[float]]:
    n, m = len(M), len(M[0])
    return [[M[i][j] for i in range(n)] for j in range(m)]


def mat_mul(A: list[list[float]], B: list[list[float]]) -> list[list[float]]:
    n, k = len(A), len(A[0])
    m = len(B[0])
    out = [[0.0] * m for _ in range(n)]
    for i in range(n):
        for t in range(k):
            a = A[i][t]
            if a == 0.0:
                continue
            brow = B[t]
            orow = out[i]
            for j in range(m):
                orow[j] += a * brow[j]
    return out


def mat_vec(A: list[list[float]], v: list[float]) -> list[float]:
    return [sum(A[i][j] * v[j] for j in range(len(v))) for i in range(len(A))]


def vec_norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def vec_scale(v: list[float], s: float) -> list[float]:
    return [x * s for x in v]


def vec_dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def frobenius(M: list[list[float]]) -> float:
    return math.sqrt(sum(x * x for row in M for x in row))


def mat_sub(A: list[list[float]], B: list[list[float]]) -> list[list[float]]:
    return [[A[i][j] - B[i][j] for j in range(len(A[0]))] for i in range(len(A))]


def power_iteration(
    A: list[list[float]], rng: random.Random, iters: int = 64
) -> tuple[float, list[float]]:
    """Largest eigenpair of symmetric A via power iteration."""
    n = len(A)
    v = [rng.uniform(-1.0, 1.0) for _ in range(n)]
    nv = vec_norm(v)
    if nv < 1e-18:
        v = [1.0] + [0.0] * (n - 1)
    else:
        v = vec_scale(v, 1.0 / nv)
    for _ in range(iters):
        Av = mat_vec(A, v)
        nv = vec_norm(Av)
        if nv < 1e-18:
            return 0.0, v
        v = vec_scale(Av, 1.0 / nv)
    Av = mat_vec(A, v)
    lam = vec_dot(v, Av)
    return lam, v


def svd_singular_values(
    M: list[list[float]], rng: random.Random, k: int | None = None, iters: int = 64
) -> list[float]:
    """
    Top-k singular values of M via eigen-deflation on M Mᵀ (stdlib only).
    For n≤32 this is cheap enough for a build-free probe.
    """
    n = len(M)
    if k is None:
        k = n
    k = min(k, n)
    Mt = mat_t(M)
    gram = mat_mul(M, Mt)
    sigmas: list[float] = []
    for _ in range(k):
        lam, u = power_iteration(gram, rng, iters=iters)
        if lam < 1e-12:
            sigmas.extend([0.0] * (k - len(sigmas)))
            break
        sigmas.append(math.sqrt(max(lam, 0.0)))
        for i in range(n):
            for j in range(n):
                gram[i][j] -= lam * u[i] * u[j]
    return sigmas


def energy_in_top_w(sigmas: list[float], w: int) -> float:
    total = sum(s * s for s in sigmas)
    if total < 1e-18:
        return float("nan")
    head = sum(s * s for s in sigmas[:w])
    return head / total


def orthonormalize_columns(M: list[list[float]], eps: float = 1e-12) -> list[list[float]]:
    """Thin QR (modified Gram–Schmidt) on columns; drop near-zero columns."""
    n, m = len(M), len(M[0])
    cols = [[M[i][j] for i in range(n)] for j in range(m)]
    basis: list[list[float]] = []
    for col in cols:
        v = col[:]
        for q in basis:
            proj = vec_dot(v, q)
            v = [v[i] - proj * q[i] for i in range(n)]
        nv = vec_norm(v)
        if nv < eps:
            continue
        basis.append(vec_scale(v, 1.0 / nv))
    r = len(basis)
    out = [[0.0] * r for _ in range(n)]
    for j, q in enumerate(basis):
        for i in range(n):
            out[i][j] = q[i]
    return out


def projector_from_cols(Q: list[list[float]]) -> list[list[float]]:
    """P = Q Qᵀ for orthonormal columns in Q (n×r)."""
    if not Q or not Q[0]:
        n = len(Q)
        return [[0.0] * n for _ in range(n)]
    Qt = mat_t(Q)
    return mat_mul(Q, Qt)


def structured_b32_space_approx(
    B32f: list[list[float]], Bhatf: list[list[float]]
) -> list[list[float]]:
    """
    Approx B̂' = P_col(B32) · B̂ · P_row(B32).
    If Extract were (near-)linear on the thin MatExpand factors, B̂ would live
    near these spaces and the residual would be tiny.
    """
    Qcol = orthonormalize_columns(B32f)
    Qrow = orthonormalize_columns(mat_t(B32f))
    Pcol = projector_from_cols(Qcol)
    Prow = projector_from_cols(Qrow)
    return mat_mul(mat_mul(Pcol, Bhatf), Prow)


def top_left_singular_basis(
    M: list[list[float]], k: int, rng: random.Random, iters: int = 64
) -> list[list[float]]:
    """Orthonormal basis for the top-k left singular subspace of M (n×k)."""
    n = len(M)
    k = min(k, n)
    Mt = mat_t(M)
    gram = mat_mul(M, Mt)
    basis: list[list[float]] = []
    for _ in range(k):
        lam, u = power_iteration(gram, rng, iters=iters)
        if lam < 1e-12:
            break
        basis.append(u)
        for i in range(n):
            for j in range(n):
                gram[i][j] -= lam * u[i] * u[j]
    out = [[0.0] * len(basis) for _ in range(n)]
    for j, u in enumerate(basis):
        for i in range(n):
            out[i][j] = u[i]
    return out


def subspace_cca_max(
    B32f: list[list[float]],
    Bhatf: list[list[float]],
    w: int,
    rng: random.Random,
    iters: int = 48,
) -> float:
    """
    CCA-style max correlation = cos(θ_min) between col(B32) and the top-w
    left singular subspace of B̂. Equals the largest singular value of
    Q32ᵀ U_w, hence ∈ [0, 1] (up to float noise).
    """
    Q32 = orthonormalize_columns(B32f)
    Uw = top_left_singular_basis(Bhatf, w, rng, iters=iters)
    if not Q32 or not Q32[0] or not Uw or not Uw[0]:
        return float("nan")
    M = mat_mul(mat_t(Q32), Uw)
    sigmas = svd_singular_values(M, rng, k=min(len(M), len(M[0])), iters=iters)
    if not sigmas:
        return float("nan")
    return min(1.0, max(0.0, max(sigmas)))


def round_matrix(M: list[list[float]]) -> list[list[int]]:
    return [[int(round(x)) for x in row] for row in M]


def probe_one(
    n: int, w: int, seed: int, prf_key: bytes, freivalds_trials: int = 8
) -> dict:
    rng = random.Random(seed + n * 1009)
    B32 = synthetic_matexpand_b32(n, w, rng)
    rank_b32 = matrix_rank_mod(B32)
    Bhat = extract_matrix(B32, prf_key)

    B32f = to_float(B32)
    Bhatf = to_float(Bhat)

    sigmas = svd_singular_values(Bhatf, rng, k=n)
    top_w_energy = energy_in_top_w(sigmas, w)
    cca = subspace_cca_max(B32f, Bhatf, w, rng)

    Bhat_approx_f = structured_b32_space_approx(B32f, Bhatf)
    resid_f = frobenius(mat_sub(Bhatf, Bhat_approx_f))
    norm_bhat = frobenius(Bhatf)
    rel_frob = resid_f / norm_bhat if norm_bhat > 1e-18 else float("nan")

    Bhat_approx = round_matrix(Bhat_approx_f)
    zero_freivalds = 0
    residuals: list[int] = []
    for t in range(freivalds_trials):
        r = freivalds_residual(Bhat, Bhat_approx, random.Random(seed + n + t * 17))
        residuals.append(r)
        if r == 0:
            zero_freivalds += 1

    return {
        "n": n,
        "w": w,
        "rank_b32": rank_b32,
        "sigma_head": [round(s, 6) for s in sigmas[: min(8, len(sigmas))]],
        "top_w_energy": top_w_energy,
        "cca_max": cca,
        "rel_frob_residual": rel_frob,
        "freivalds_residuals": residuals,
        "freivalds_zero_count": zero_freivalds,
        "freivalds_trials": freivalds_trials,
    }


def interpret(results: list[dict]) -> int:
    """
    Soft smoke: we expect Extract to destroy thin B32 structure.
    Soft FAIL (investigate) if every n shows near-perfect structured approx.
    Never maps to packet §0.1 FAIL by itself.
    """
    print()
    print(
        "Interpretation: SVD/CCA residuals are empirics for checklist A5 / GAP-B3. "
        "A §0.1 cost-model win is REQUIRED to claim FAIL. "
        "Empirics alone ≠ C-15 closed. C-15 remains OPEN."
    )

    suspicious = 0
    for r in results:
        if (
            r["rel_frob_residual"] < 0.05
            and r["top_w_energy"] > 0.98
            and r["cca_max"] > 0.98
            and r["freivalds_zero_count"] == r["freivalds_trials"]
        ):
            suspicious += 1
            print(
                f"WARN: n={r['n']} looks like a near-linear spectral collapse "
                f"(investigate; still need §0.1 costing to claim FAIL)"
            )

    if suspicious == len(results) and results:
        print("FAIL(smoke): every n showed near-perfect B32-space approx — investigate C-15")
        return 1

    print("PASS (spectral/approx probe smoke; not a §0.1 verdict)")
    return 0


def run(ns: tuple[int, ...], w: int, seed: int) -> int:
    vectors = load_vectors()
    prf_key = derive_matexpand_prf_key(vectors["seed_w_hex"])
    results: list[dict] = []

    for n in ns:
        if w > n:
            print(f"SKIP n={n}: w={w} > n (need w ≤ n)", file=sys.stderr)
            continue
        r = probe_one(n, w, seed, prf_key)
        results.append(r)
        print(
            f"n={r['n']} w={r['w']} rank(B32)={r['rank_b32']} "
            f"top-{w} energy={r['top_w_energy']:.6f} "
            f"CCA_max={r['cca_max']:.6f} "
            f"rel_Frob={r['rel_frob_residual']:.6f} "
            f"Freivalds zeros={r['freivalds_zero_count']}/{r['freivalds_trials']}"
        )
        print(f"  σ_head={r['sigma_head']}")
        print(f"  Freivalds residuals={r['freivalds_residuals']}")

    if not results:
        print("FAIL: no n probed", file=sys.stderr)
        return 1
    return interpret(results)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--n",
        type=int,
        nargs="*",
        default=list(DEFAULT_NS),
        help="matrix sizes to probe (default: 8 16 32)",
    )
    p.add_argument("--w", type=int, default=4, help="toy panel width / rank bound")
    p.add_argument("--seed", type=int, default=1, help="RNG seed")
    args = p.parse_args(argv[1:])
    return run(ns=tuple(args.n), w=args.w, seed=args.seed)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main(sys.argv))
