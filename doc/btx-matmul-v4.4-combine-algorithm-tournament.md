# MatMul v4.4 — Combine algorithm tournament (CPU baselines)

Status: **miner-local exact alternatives**. Consensus digest bytes are unchanged
unless a path is proven byte-identical (pinned by unit tests). Public activation
remains inert (`INT32_MAX`).

Companion hardening note: `doc/btx-matmul-v4.4-lt-hardening-response-2026-07-19.md`
§6/§8 (publish fastest known exact algs; do not change the integer transcript
until measured).

## Lanes under test

| Lane | Symbol | Role |
|---|---|---|
| Classical per-MAC Fq | `ComputeCombineModQClassical` | Pre-deferred oracle |
| Deferred `__int128` | `ComputeCombineModQ` | Consensus ALU reference (byte-identical to classical) |
| Limb-tensor 16 | `ComputeCombineLimbTensorBMX4C` | Consensus tensor-shaped reference |
| Karatsuba-9 | `ComputeCombineKaratsuba9BMX4C` | Preferred miner INT8 combine |
| Adaptive limb | `ComputeCombineAdaptiveLimbBMX4C` | Two-limb base-64 when safe; else adaptive base-256 with zero-plane skip; else Karatsuba-9 |

All five MUST produce identical `Chat` / `SerializeSketch` bytes on every fixture
the harness runs. Identity failure voids the timing row.

## How to run (CPU only)

```bash
./build/src/bench/bench_btx -filter=MatMulV4CombineTournament
```

Test dims only (`n∈{64,96,128}`). Production `n=4096` is out of scope here —
use `matmul_v4_stage_bench` / silicon soak for that.

## How to read results

- Prefer the **fastest identity-PASS lane** as the ASERT calibration baseline
  (“fastest known exact”), not a schoolbook MAC count.
- Deferred `__int128` should beat classical per-MAC Fq on CPU (fewer reductions).
- Adaptive limb wins when magnitude scan keeps high planes empty / two-limb-safe;
  at full envelope it should track Karatsuba-9 or three-limb base-256.
- There is **no** claimed “≤12.5% Strassen cap” or “no cheaper mathematical path”
  — those postures are retired (audit F2 / leap checklist). Constant-factor exact
  algorithm edges are ordinary miner efficiency; calibrate difficulty to the
  measured fastest exact path.

## Consensus vs miner-local

| Path | Consensus-identical? | Notes |
|---|---|---|
| `ComputeCombineModQ` (deferred) | **Yes** — replaces classical as the ALU reference; classical kept as public oracle | Proven by `deferred_combine_matches_classical_max_dim_adversarial` |
| Limb / Karatsuba-9 / FP8-five | **Yes** when used | Existing identicality tests |
| Adaptive limb / two-limb / base-256 | **Yes when selected** (identical Chat); **miner-local dispatch** | Not required on the verifier path; verifier still uses Freivalds |
| Changing which lane digests commit | **Forbidden** unless byte-identical | Hard-fork window still does not alter transcript bytes without proof |
