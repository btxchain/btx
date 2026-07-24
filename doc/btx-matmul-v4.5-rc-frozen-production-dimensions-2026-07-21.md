> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# ENC_RC provisional frozen production dimensions — 2026-07-21

**PROVISIONAL / Stage-G-calibratable.** Freezing ≠ activation.
`nMatMulRCHeight` and `nMatMulRCCoupledHeight` remain `INT32_MAX`.
ExactReplay stays consensus; GKR arbiter OFF.

## Episode (ENC_RC)

`MakeProductionRCEpisodeParams()` ≡ `DefaultConsensusRCEpisodeParams()`
(= `EpisodeParamsFromScale({kRCW0Res, kRCW0Cap})`):

| Field | Value |
|---|---|
| `n_ctx` | 786432 |
| `d_head` | 128 |
| `n_q` | 512 |
| `d_model` | 4096 |
| `b_seq` | 16384 |
| `L_lyr` | 16 |
| `rounds` | 4 |
| `T_leaf` | 1024 |

Harness: `--production`. CI default remains `--toy` / `--medium`.

## Coupled puzzle (ENC_RC_COUPLED)

`MakeProductionRCCoupParams()`:

| Field | Value | Notes |
|---|---|---|
| `barriers` | 8 | C5 upper bound |
| `lobes` | 8 | |
| `lobe_width` | 8192 | MX-aligned, power-of-two |
| `bank_pages` | 768 | |
| `StateBytes()` | 65536 | pow2 + MX-aligned |

### Peak-byte formulas

```
page     = lobe_width²                         # int8 bank page
streamed = page + StateBytes + 8·StateBytes + 32·barriers
resident = bank_pages·page + StateBytes + 8·StateBytes + 32·barriers
```

| Mode | Estimate / measured (Lane C / tip bf36b7d / 5060 Ti) |
|---|---|
| Streamed | peak est **64.56 MiB**; **wall 985.98–990.55 s** across 512 MiB / 2 GiB / 8 GiB / uncapped (mean ≈ **989.1 s**) |
| Resident | **~48.00 GiB** — **INFEASIBLE-ON-16GB** |

Digest (Streamed, CUDA, parity vs CPU):
`a3e485f132e04b3ebd9dd4a057b61ae5f49a16593e488caa56155589d3c0c868`.

Param fingerprint (CI-pinned, not puzzle digest):
`9e5572c7a6d936e35dd68319a59a1d76d1f0762d5c07f441598ebd1c41d04869`.

`ResolveRCCoupParams` still returns toy/medium until a **separate consensus
decision** wires production into public nets.

## Memory-cap methodology

- `--mem-cap BYTES`: if Resident estimate exceeds cap → auto-select **Streamed**
  (tile; never OOM-reject if Streamed fits). Soft mode-select — measured peak
  RSS ≈1.26 GiB can exceed a 512 MiB soft floor while still Streamed.
- `--mem-cap-sweep`: production coupled under 512 MiB / 2 GiB / 8 GiB (+uncapped).
- Production harness defaults to Streamed-only; set
  `BTX_RC_COUP_ALLOW_RESIDENT=1` to also time Resident on ≥48 GiB hosts.
- Resident-vs-Streamed slowdown: **N/A on 16 GB** (Resident not runnable).

## Lane C Stage-I verify / ExactReplay (from C2 + in-progress C1b)

| Profile | Cores | Path @ production dims | measured_s | Budget_s | Meet? |
|---|---|---|---|---|---|
| floor/mid/dc | 4 / 8 / 24 | happy-path @ **toy** | 0.286–0.287 | 0.9 | **YES** |
| floor/mid/dc | 4 / 8 / 24 | happy-path @ **medium** | 0.511–0.513 | 0.9 | **YES** |
| floor/mid/dc | — | happy-path @ **production** | **NOT RUN** | 0.9 | TBD |
| dc | all | ExactReplay ε=0 @ production | **≥8416 s / ~2.3 h** (C1b in progress) | 9.0 / 90 | **NO** (lower bound) |

Harness: `--production --prove-winner-gkr` for succinct; `--production --backend cpu`
for ExactReplay. Coupled: `--coupled-production` (+ `--mem-cap-sweep`). Pin with
`taskset` (no in-binary validator-profile flag).

### C5 verdict

> Production ExactReplay **≥8416 s** (still running) → **busts** 9.0 s and 90 s.
> Floor/mid/dc succinct verify **clears** 0.9 s at toy/medium (0.29 / 0.51 s);
> production GKR not yet measured. Coupled Streamed Mine ≈ **989 s**; Resident
> **INFEASIBLE-ON-16GB**. Points to **activate Stage-I succinct verify**
> (pending production verify measure) **or shrink episode**. Height stays
> `INT32_MAX`.

## C4 Stage-G note (16 GB)

Lane C C4 on RTX 5060 Ti **16 GB**:
`medium_k_est` mean **1.229** (min 1.226 / max 1.231) vs gate target **1.3** →
**NO-GO**.

## Caveat

Throughput separation GPU vs CPU is a **Stage-G consensus-dim** result.
Toy/medium cannot raise height. Gate verdict remains **NO-GO** until silicon
economics + interconnect + Stage-I verify tables close (production ExactReplay
wall + production happy-path verify still needed for a final C5 paragraph).
