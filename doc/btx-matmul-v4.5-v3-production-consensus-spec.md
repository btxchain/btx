> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul v4.5 — ENC_RC / ENC_RC_COUPLED V3 production consensus specification

**Status:** INTEGRATED — V3 production is the default coupled profile (`nMatMulRCCoupledProfile` defaults to `3`; the aggregate `RCCoupConsensusConfig{}` default `transcript_version` is `ENC_RC_V3`). Public activation heights remain `INT32_MAX`. GKR arbiter OFF. No hardware attestation.

**Base tip:** `f861bd5` → integration `wip/v45-production-coupled`.

## 1. Configuration version

| Version | Role |
|---------|------|
| V1 | Legacy toy / single-page schedule goldens (frozen) |
| V2 | 768 pages, M=1, 12 pages/slot — int8 48 GiB, **packed ≈ 25.5 GiB** (frozen; not a 48 GiB packed floor) |
| V3 | Integrated production default below (new domain tags + goldens) |

`kRCCoupConsensusConfigVersionV3 = 3`.

## 2. V3 parameters (integrated production default)

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
| V2 (regression-only) | 768 | 12 | 1 | 48 | **25.5** | 0.048 |
| V3 (production default) | 1536 | 24 | 128 | 96 | **51** | **12** |
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

| Domain | V1 | V2 | V3 |
|--------|----|----|-----|
| episode | `BTX_RC_COUP_EPISODE_V1` | `…_V2` | `…_V3` |
| bank | `BTX_RC_COUP_BANK_V1` | `…_V2` | `…_V3` |
| lobe | `BTX_RC_COUP_LOBE_V1` | `…_V2` | `…_V3` |
| barrier | `BTX_RC_COUP_BARRIER_V1` | `…_V2` | `…_V3` |
| perm | `BTX_RC_COUP_PERM_V1` | `…_V2` | `…_V3` |
| mix | `BTX_RC_COUP_MIX_V1` | `…_V2` | `…_V3` |
| extract | `BTX_RC_COUP_EXTRACT_V1` | `…_V2` | `…_V3` |
| full-bank | `BTX_RC_COUP_FULL_BANK_V1` | `…_V2` | `…_V3` |
| exchange | `BTX_RC_COUP_MAT_XCHG_V1` | `…_V2` | `…_V3` |
| exchange rounds | `BTX_RC_COUP_MAT_XCHG_ROUNDS_V3` (rounds>0 only) | same | same |

Selection: `RCCoupDomainTagsForVersion(RCCoupOptions::transcript_version)`. Frozen V1 toy / V2 medium goldens use `transcript_version=1` (V1 tag family). V3 CI/production use `MakeMediumV3RCCoupOptions` / `MakeV3RCCoupOptions` (`transcript_version=3`).
