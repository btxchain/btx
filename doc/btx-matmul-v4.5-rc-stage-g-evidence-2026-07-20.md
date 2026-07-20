# ENC_RC Stage G evidence — CPU box campaign (2026-07-20)

*Tip: `91a687b12638bb5a8b479eecbfe325a18d9e8eb1` (`claude/matmul-v4-design-spec-af23sj`).*
*Host: `cymacpro-linux`, Intel Xeon W-3245 @ 3.20 GHz, 32 threads, 91 GiB RAM.*
*`nvidia-smi` fails (no working NVIDIA driver). **Cannot measure real B200 / NVLink.***
*`nMatMulRCHeight` remains `INT32_MAX`. This document never recommends raising height.*

## Honesty preamble

| Claim class | Status on this box |
|---|---|
| CPU chrono walls (toy + medium) | **MEASURED** below |
| Device-resident GPU / B200 / 5090 / MI355X | **UNMEASURED** — blocker |
| NVLink-vs-PCIe ≥7× on same chips (Stage-I gate 4) | **UNMEASURED** — blocker |
| Interconnect slowdown factor | **SIMULATED only** — **NOT EVIDENCE** for Stage-I gate 4 |

## Harness

```bash
export BTX_RC_HARNESS=build/bin/matmul-v4-rc-harness
export BTX_SOURCE_REVISION=$(git rev-parse HEAD)   # 91a687b…
contrib/matmul-v4/rc-stage-g-campaign.py --all --runs 5 --episodes 3 \
  --outdir /tmp/stage-g --gate
# Profiles also via:
#   contrib/matmul-v4/measure-hardware.sh cpu --profile {coupled,coupled-medium,rc-toy,rc-medium}
```

Artifacts: `/tmp/stage-g/campaign-*.json`, `/tmp/stage-g/stage-g-summary.json`.

Software model: `src/matmul/matmul_v4_rc_coupled_netcost.h` (+ campaign Python mirror).
Default inject: `fabric_us=5`, `pcie_us=80` per barrier → exchange slowdown **16×** (**SIMULATED**).

---

## 1. Coupled puzzle (Stage C modes) — CPU

All four modes present: Sequential / Checkpointed / Streamed / Resident.
Digest toy golden `c9ac99d0…1363`; medium `2f731ec6…9eb2`. Digests matched across modes.

### Coupled toy (5 runs × 3 episodes)

| Mode | wall_s (mean) | nonce/s (mean) | peak RSS KiB (mean) | wall CV |
|---|---:|---:|---:|---:|
| Sequential | 0.000820 | 1331 | 5201 | 0.299 |
| Checkpointed | 0.002335 | 445 | 5209 | 0.213 |
| Streamed | 0.001618 | 641 | 5209 | 0.203 |
| Resident | 0.000674 | 1514 | 5213 | 0.170 |

- Episode wall mean (Sequential): **0.000820 s**; cross-run CV **0.299**
- Peak RSS (process): **18992 KiB**
- Streamed / Resident: **≈1.99×** (≥1 as expected — paging cost)

### Coupled medium (5 runs × 3 episodes)

| Mode | wall_s (mean) | nonce/s (mean) | peak RSS KiB (mean) | wall CV |
|---|---:|---:|---:|---:|
| Sequential | 0.007759 | 171 | 5319 | 0.505 |
| Checkpointed | 0.024412 | 42.6 | 5319 | 0.241 |
| Streamed | 0.011828 | 102 | 5319 | 0.518 |
| Resident | 0.003627 | 278 | 5319 | 0.110 |

- Episode wall mean (Sequential): **0.007759 s**; cross-run CV **0.505** (exceeds §8 10% kill — honest CPU noise / cache warm-up on tiny walls)
- Peak RSS (process): **19248 KiB**
- Streamed / Resident: **≈2.19×**

---

## 2. RC episode harness — CPU

### RC toy (5 runs × 3 episodes)

| Phase | mean wall_s |
|---|---:|
| phase1 | 0.000568 |
| phase2 | 0.000889 |
| phase3 | 0.000337 |
| total | **0.001803** |

| Exec mode | wall_s (mean) | peak RSS KiB | wall CV |
|---|---:|---:|---:|
| Resident | 0.001152 | 19248 | 0.234 |
| Checkpointed | 0.001402 | 19248 | 0.239 |
| Streamed | 0.001344 | 19248 | 0.274 |

- Cross-run episode CV: **0.298**
- Streamed / Resident: **≈1.27×** (≥1)

### RC medium (5 runs × 3 episodes)

| Phase | mean wall_s |
|---|---:|
| phase1 | 0.000372 |
| phase2 | 0.045310 |
| phase3 | 0.014840 |
| total | **0.06054** |

| Metric | Value |
|---|---:|
| cross-run CV | **0.0556** (≤5% GO bound) |
| peak RSS KiB | **19248** |

| Exec mode | wall_s (mean) | wall CV |
|---|---:|---:|
| Resident | 0.05767 | 0.083 |
| Checkpointed | 0.06910 | 0.025 |
| Streamed | 0.06797 | 0.006 |

- Streamed / Resident: **≈1.22×** (≥1)

---

## 3. Interconnect SIMULATION (NOT silicon)

| Parameter | Value |
|---|---|
| `fabric_us` / barrier | 5 |
| `pcie_us` / barrier | 80 |
| barriers (toy / medium) | 4 / 8 |
| exchange slowdown (pcie/fabric) | **16×** |
| Stage-I gate 4 threshold | ≥7× on **same chips** |
| `stage_i_gate4_pass` | **false** (simulated ⇒ never pass) |

**Label: SIMULATED / NOT EVIDENCE for Stage-I gate 4.** Real B200/MI355X NVLink-vs-PCIe campaigns still required.

---

## 4. rc-gate Stage G verdict (this box)

```
VERDICT: NO-GO
nMatMulRCHeight stays INT32_MAX
```

| Report | G1 | G2 | G3 | G4 | Notes |
|---|---|---|---|---|---|
| campaign-coupled | pass | toy-pass | toy-pass | toy-pass | toy PARTIAL path only |
| campaign-coupled-medium | pass | partial | fail | partial | medium ≠ production; G3 synthetic refused |
| campaign-rc-toy | pass | toy-pass | toy-pass | toy-pass | toy PARTIAL path only |
| campaign-rc-medium | pass | partial | fail | partial | medium ≠ production; G3 synthetic refused |

**Aggregate: NO-GO** (mixed medium + missing GPU/NVLink + SIMULATED interconnect).

Explicit blockers recorded in campaign JSON / gate reasons:

1. GPU campaign missing (`nvidia-smi` failed) — no device-resident walls
2. NVLink-vs-PCIe silicon campaign missing — Stage-I gate 4 UNMEASURED
3. Interconnect factor 16× is SIMULATED / NOT EVIDENCE
4. Nonempty reports never PASS without numeric G2/G3/G4 at production dims
5. Stage G never GO without measured walls + variance + residency fields (present here, but residency=`device_resident:false`)

---

## 5. File index (this wave)

| Path | Role |
|---|---|
| `contrib/matmul-v4/rc-stage-g-campaign.py` | Same-tip multi-run campaign driver |
| `contrib/matmul-v4/measure-hardware.sh` | `--profile coupled\|coupled-medium\|rc-toy\|rc-medium` |
| `contrib/matmul-v4/rc-gate.py` | Campaign JSON + Stage G blockers; never GO without walls/variance/residency |
| `src/matmul/matmul_v4_rc_coupled_netcost.h` | SIMULATED fabric vs PCIe inject |
| `src/matmul-v4-rc-harness.cpp` | Coupled + RC mode-sweep + RSS + tip provenance |

---

*End. CPU evidence only. Silicon Stage G remains OPEN.*
