> **HISTORICAL DESIGN / AUDIT EVIDENCE — MatMul v4.7 roadmap takes precedence.**
> This document preserves version-local findings, names, and measurements; it is not
> the current activation plan. The proposed transition is defined by
> `doc/btx-matmul-v4.7-transition-roadmap.md`: Epoch A uses Profile 1 with
> ExactReplay authority and optional shadow proofs; Epoch B requires both a durable
> Profile-1 proof and ExactReplay; Epoch C makes the Profile-1 proof authoritative;
> and Epoch D separately moves to Profile 2 under proof authority. Mainnet Epoch A (v4 = BMX4C = RC) now activates at height 182'283; all other transition heights remain disabled. Any older “production,” “default,” “shipping,” direct-fork,
> sampled-verifier, or coupled-profile recommendation below is historical unless the
> canonical roadmap expressly carries it forward.

# V3 B200 ↔ RTX 5090 measurement protocol

## Outcome label (current)

**PLAUSIBLE BUT UNMEASURED** — no matched B200 or RTX 5090 runs on this branch yet. Rack evidence is RTX 5060 Ti only (compile / SM120a / exactness), not performance economics.

## Required modes

Resident packed, Resident expanded int8, Streamed pinned-host, partial cache + stream, partial cache + regen, multi-GPU shard, native MXFP4, exact INT8 fallback.

## Required dimensions

- V2 768 diagnostic (packed 25.5 GiB)<br>
- V3 1536 / M=128 / 51 GiB packed / 12 TiMAC<br>
- Packed sweeps near 48/64/80/96 GiB (page counts ÷ 64)<br>
- Q sweeps: 1, 8, 32, 128, 256, 512, 1024 where memory permits<br>

## Record per run

git SHA, dirty state, binary hash, CUDA/driver, GPU UUID/clocks/power, backend name, native instruction evidence (`QMMA.SF` / SM100 recipe), packed/expanded bytes, residency mode, PCIe/NVLink traffic, device-event time, host wall separately, p50/p95/CV, joules/nonce, **absolute** nonce/s, CPU/GPU exactness, `peak_ready` + every prerequisite.

Never use relative-only speedups for card comparisons. Rental prices are dated inputs, never consensus constants.

## Economic GO (screenshot claim)

`B200_nonce/s / 5090_nonce/s > B200_$/hr / 5090_$/hr` with safety margin, 5090 using best legal Streamed strategy. If unmet: report FAILED reason (capacity / batching / regen / PCIe / tensor underuse / rent gap / shortcut).
