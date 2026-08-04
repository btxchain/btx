# Epoch-A ASERT schema-4 calibration corpus — CUDA launch cohort (2026-08-04)

The first assembled schema-4 corpus for the Epoch-A ASERT coefficient. Until
this, `kRCEpochAAsertRescaleNum` carried a staged value with no corpus behind it.

## Freeze

| | |
|---|---|
| Source revision | `0a1769cdff12d1a18488b295075e737ee3b5e4f2` |
| Build-relevant fingerprint | `6158de794bb33308e8f6bd1b7680bb31d68b84834c8bf546b14ef9bed35d0f79` |
| Parent binary | `8cd863d2ee80c8168f52a00def84f073179156fde5842c929de17fc5697211fb` |
| RC harness | `4cf5b820c825419f6af67ca5b548fd0691d1a590d6eda3c5e105f52bb410ae06` |

## Measurement

| | |
|---|---|
| Parent, max of 5 mixed samples | 331,891,937 attempts/s |
| RC, max of 8 Profile-1 episodes | 12.073250614 s |
| **Derived coefficient** | **4,007,014,530 / 1** |
| Governance inputs | `safety_margin_bps=0`, `coefficient_quantum=1` |

Parent samples used 2x10^9 tries each (~6 s per sample), spread 328.5M–331.9M
attempts/s. The RC series is the sealed golden corpus for this revision;
per-episode wall times 11.98–12.06 s, and an independent re-run on an idle host
using the identical harness binary reproduced 12.015 s mean.

## Why CUDA only

Difficulty calibration is bound to the CUDA launch cohort by policy. The
coefficient converts v3 parent nonce-attempt rate into RC episode cost, so it
must describe the hardware that will actually mine the fork, and that cohort is
CUDA-dominated. An M4-class Metal provider is roughly 5x slower per RC episode;
including it in a maximum-envelope selection would set network difficulty from a
provider contributing negligible hashrate.

Metal remains a **required** provider for golden-corpus reproduction, which is a
separate and unchanged correctness gate: CUDA and Metal must derive
byte-identical digests. See `RCProductionGoldenManifestCohortValid`, which still
demands both families. Do not conflate the two.

## Relationship to the installed coefficient

The installed `kRCEpochAAsertRescaleNum` is **6,931,159,304**, which is 1.730x
this measured envelope. It is installed as a deliberately conservative ratified
policy coefficient, not as a reproduction of this measurement, because:

- the error is asymmetric. Too low risks slow or stalled blocks at the fork; too
  high yields temporarily fast blocks that ASERT corrects within an epoch;
- the historical CUDA campaign that produced it measured ~215.36M attempts/s and
  ~32.18 s per RC episode on a different device class, and this cohort's own RC
  timing has been observed in two clusters (~12 s and ~32 s) across builds on the
  same GPU without a resolved explanation. The installed value lies between the
  coefficients those two clusters imply;
- the staged constant is not exactly reproducible from the retained historical
  artifacts, which yield 6,898,853,852. Those artifacts are classified
  historical and non-authorizing.

This corpus therefore establishes a measured lower bound and binds it to exact
binaries, revision, backend and raw samples. It neither reproduces nor, by
itself, ratifies the installed override, and it is not bound to the final
activation height/source tuple. Recalibrate and record the reviewed coefficient
decision on the exact final tree if the representative launch cohort changes.

## Contents

- `epoch-a-asert-root.json` — schema-4 assembled corpus
- `derived.json` — derivation output
- `rig-cuda.json` — per-rig assembly
- `raw/parent-{1..5}.json` — schema-3 mixed parent samples
