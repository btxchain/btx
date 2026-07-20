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

| Mode | Estimate |
|---|---|
| Streamed | **64.56 MiB** (≪ 24 GiB commodity; ≤ 512 MiB soft floor) |
| Resident | **~48.00 GiB** (datacenter HBM class) |

Param fingerprint (CI-pinned, not puzzle digest):
`9e5572c7a6d936e35dd68319a59a1d76d1f0762d5c07f441598ebd1c41d04869`.

`ResolveRCCoupParams` still returns toy/medium until a **separate consensus
decision** wires production into public nets.

## Memory-cap methodology

- `--mem-cap BYTES`: if Resident estimate exceeds cap → auto-select **Streamed**
  (tile; never OOM-reject if Streamed fits).
- `--mem-cap-sweep`: production coupled under 512 MiB / 2 GiB / 8 GiB.
- Production harness defaults to Streamed-only; set
  `BTX_RC_COUP_ALLOW_RESIDENT=1` to also time Resident on ≥48 GiB hosts.

## Caveat

Throughput separation GPU vs CPU is a **Stage-G consensus-dim** result.
Toy/medium cannot raise height. Gate verdict remains **NO-GO** until silicon
economics + interconnect + Stage-I verify tables close.
