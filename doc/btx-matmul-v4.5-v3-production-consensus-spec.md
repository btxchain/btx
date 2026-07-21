# BTX MatMul v4.5 — ENC_RC / ENC_RC_COUPLED V3 production consensus specification

**Status:** HYPOTHESIS / design-locked for implementation. Public activation heights remain `INT32_MAX`. GKR arbiter OFF. No hardware attestation.

**Base tip:** `f861bd5` → integration `wip/v45-production-coupled`.

## 1. Configuration version

| Version | Role |
|---------|------|
| V1 | Legacy toy / single-page schedule goldens (frozen) |
| V2 | 768 pages, M=1, 12 pages/slot — int8 48 GiB, **packed ≈ 25.5 GiB** (frozen; not a 48 GiB packed floor) |
| V3 | Preferred production hypothesis below (new domain tags + goldens) |

`kRCCoupConsensusConfigVersionV3 = 3`.

## 2. V3 parameters (preferred hypothesis)

| Field | Value |
|-------|-------|
| barriers | 8 |
| lobes | 8 |
| rows_per_lobe (M) | 128 |
| width W (=K=N) | 8192 |
| bank_pages | 1536 |
| pages_per_barrier_lobe | 24 |
| coverage | 8 × 8 × 24 = 1536 (exact once) |
| packed bytes | 1536 × 8192² × 17/32 = **51 GiB** |
| expanded int8 | 1536 × 8192² = **96 GiB** |
| MACs/nonce | M × P × B × L × W² = **12 TiMAC** |
| active state | 8 × 128 × 8192 = 8 MiB |
| int64 acc slab | 64 MiB |

## 3. Comparison table

| Profile | pages | P/slot | M | int8 GiB | packed GiB | TiMAC |
|---------|-------|--------|---|----------|------------|-------|
| V2 (current) | 768 | 12 | 1 | 48 | **25.5** | 0.048 |
| V3 (hypothesis) | 1536 | 24 | 128 | 96 | **51** | **12** |
| Sweep ~48 packed | ≈1448* | — | — | — | ~48 | — |
| Sweep ~64 packed | ≈1928* | — | — | — | ~64 | — |
| Sweep ~80 packed | ≈2410* | — | — | — | ~80 | — |
| Sweep ~96 packed | ≈2892* | — | — | — | ~96 | — |

\*Page counts for sweeps should be rounded to multiples of `barriers×lobes=64` after TMTO audit.

## 4. Canonical packed bank

- Mantissas: E2M1 nibbles (32 elems → 16 bytes)
- Scale: UE8M0 per 32 K-elements (1 byte)
- **17/32 bytes/element**; provider padding excluded from consensus floor
- Merkle / bank commitment binds expanded or packed form as specified in page derivation
- Decode must bit-match CPU ExpandMx oracle for consensus values

## 5. Consensus rules (hard)

- Never read environment variables for digests
- Never inspect GPU model / VRAM / driver / backend
- Fixed subsidy + ASERT; hardware share only via exact-work throughput
- Checked arithmetic / fixed ring — no C++ signed overflow UB
- Unified activation predicate; heights stay `INT32_MAX` until GO criteria met

## 6. TMTO / regeneration gate

V3’s 51 GiB packed floor is **NO-GO** if Agent B / audit shows seed regeneration or compression lets a 32 GiB card avoid the intended wall-time cost. See `btx-matmul-v4.5-v3-packed-bank-audit.md`.

## 7. Proof binding (high level)

Header/template/nonce, V3 config, packed-bank commitment, full page coverage, M=128 GEMMs, accumulation, permutation, exchange, Extract, barrier roots, final digest/target. GKR details in soundness status doc; arbiter remains OFF.

## 8. Domain tags

New V3 tags must not collide with V1/V2 (`*_V3` suffixes). Do not silently retarget V1/V2 goldens.
