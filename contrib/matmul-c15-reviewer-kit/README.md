# MatMul v4.4-LT — C-15 reviewer kit

**Status: C-15 OPEN.** ChaCha20-PRF MatExpand Extract is a *candidate* with
frozen CPU goldens. This kit lets an external cryptanalyst reproduce Extract
and toy collapse experiments **without building bitcoind / the full node**.

Do **not** treat a green run of these scripts as cryptographic closure, Rank-1
GO, or permission to raise `nMatMulDRLTHeight`.

## Contents

| File | Purpose |
|---|---|
| `test-vectors.json` | Frozen Extract goldens, PRF tag, MANT/SCLE lanes, endian notes; **`reduction_relevant_finding_notes`** (high R² / zero Freivalds residual / truncated salt) |
| `reference_extract.py` | Standalone Python ChaCha20-PRF Extract (stdlib only) |
| `toy_attack_harness.py` | Toy-`n` synthetic MatExpand + poly R² for deg 1..`--degree` (default 3) + Freivalds residual |
| `spectral_approx_probe.py` | Stdlib SVD/CCA-style residual vs Extract for `n∈{8,16,32}` (Gap #6) |
| `spectral_approx_probe.md` | Empirics ≠ §0.1 FAIL; C-15 stays OPEN |
| `rank_spectral_regression.md` | `rank(B32) ≤ w` note and smoke procedure |
| `named-assumption.md` | Pointer to packet **§0.2** (`BTX-C15-NonCollapse-v1`, unreduced) |
| `reduction-attack-checklist.md` | Step-by-step firm attacks mapped to §0.1 FAIL; **LFR taxonomy** (linear Freivalds rewrites beyond affine/shared-φ; heuristic vs theorem) |

## Requirements

- Python 3.10+ (stdlib only: `hashlib`, `json`, `struct`, …)
- No `bitcoind`, Boost, CMake, or GPU toolchain

## Quick start

```bash
cd contrib/matmul-c15-reviewer-kit

# 1) Verify frozen Extract goldens (must print PASS)
python3 reference_extract.py

# 2) Toy collapse harness (expect low R² for deg 1..3 + nonzero Freivalds residual)
python3 toy_attack_harness.py --n 8 --w 4
python3 toy_attack_harness.py --n 16 --w 4 --seed 7 --degree 3

# 3) Spectral / approx-B̂ probe (SVD/CCA residuals; empirics ≠ §0.1 FAIL)
python3 spectral_approx_probe.py
```

Firm pointers (read before filing a finding):

- Named assumption: [`named-assumption.md`](named-assumption.md) → packet **§0.2** `BTX-C15-NonCollapse-v1`
- Attack menu: [`reduction-attack-checklist.md`](reduction-attack-checklist.md) → §0.1 FAIL surfaces

## Normative packet (read this)

Full adversarial brief and deliverable tables:

- [`doc/btx-matmul-v4.4-lt-external-c15-packet.md`](../../doc/btx-matmul-v4.4-lt-external-c15-packet.md)

Companions: normative spec + adversarial analysis under `doc/btx-matmul-v4.4-lt-*.md`.

In-tree witnesses (optional; requires a node build) in
`src/test/matmul_v4_lt_tests.cpp`:

- `matexpand_chacha_prf_golden_vectors`
- `matexpand_position_salt_differential` (full-width `(i,j)` high-half)
- `matexpand_extract_r2_nonapproximability` (affine / deg-2/3 R² < 0.05)
- `matexpand_c15b_affine_surrogate_sketch_rejected` (forged sketch vs
  `VerifySketchBMX4CLT`)

## Endianness (consensus-critical)

Bitcoin `uint256` hex (`GetHex` / `FromHex`) is **byte-reversed** relative to
`bytes.fromhex()`. The reference hashes **little-endian memory bytes**:

```
prf_key = SHA256("BTX_MATEXPAND_PRF_V44LT" ‖ seed_w_le)
```

ChaCha20 nonce packing, lane constants `MANT`/`SCLE`, and exact-mul scale are
pinned in `test-vectors.json` and mirrored in `reference_extract.py`.

## Expected toy outcome

Rejection of affine / low-degree collapse is **expected**. High R² or a
systematic zero Freivalds residual on dense samples would be a C-15 finding —
please report it with vectors. Spectral/CCA toy residuals
([`spectral_approx_probe.md`](spectral_approx_probe.md)) are the same class:
interesting only if costed to a **§0.1** win. C-15 remains **OPEN**.
