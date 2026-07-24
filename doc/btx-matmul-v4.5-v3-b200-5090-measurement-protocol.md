> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# V3 B200 ↔ RTX 5090 measurement protocol

## Outcome label (current)

**PLAUSIBLE BUT UNMEASURED** — no matched B200 or RTX 5090 runs on this branch yet. Rack evidence is RTX 5060 Ti only (compile / SM120a / exactness), not performance economics.

## Required modes

Resident packed, Resident expanded int8, Streamed pinned-host, partial cache + stream, partial cache + regen, multi-GPU shard, native MXFP4, exact INT8 fallback.

## Required dimensions

- V2 768 diagnostic (packed 25.5 GiB)  
- V3 1536 / M=128 / 51 GiB packed / 12 TiMAC  
- Packed sweeps near 48/64/80/96 GiB (page counts ÷ 64)  
- Q sweeps: 1, 8, 32, 128, 256, 512, 1024 where memory permits  

## Record per run

git SHA, dirty state, binary hash, CUDA/driver, GPU UUID/clocks/power, backend name, native instruction evidence (`QMMA.SF` / SM100 recipe), packed/expanded bytes, residency mode, PCIe/NVLink traffic, device-event time, host wall separately, p50/p95/CV, joules/nonce, **absolute** nonce/s, CPU/GPU exactness, `peak_ready` + every prerequisite.

Never use relative-only speedups for card comparisons. Rental prices are dated inputs, never consensus constants.

## Economic GO (screenshot claim)

`B200_nonce/s / 5090_nonce/s > B200_$/hr / 5090_$/hr` with safety margin, 5090 using best legal Streamed strategy. If unmet: report FAILED reason (capacity / batching / regen / PCIe / tensor underuse / rent gap / shortcut).
