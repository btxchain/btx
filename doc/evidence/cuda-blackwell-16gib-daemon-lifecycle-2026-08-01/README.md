# CUDA daemon lifecycle (foreground / `-daemon` / `-daemonwait`)

Status: hardware-gated functional regression **passed** on PR tip
`c4ac2e439ac496245f12dcbf8b42c9575247dbe9` for MatMul v4.7 Epoch A CUDA
initialization across fork modes.

This does **not** clear ratification gates, invent production goldens, or claim
activation readiness. The committed launch-candidate golden manifest remains
empty (`missing_golden` canary). See the
[canonical transition roadmap](../../btx-matmul-v4.7-transition-roadmap.md)
and
[code readiness resolution](../../btx-matmul-v4.7-code-readiness-resolution-2026-07-31.md).

## Hardware class (sanitized)

- OS: Linux x86_64
- CPU: Intel Xeon W-class workstation CPU (24 logical CPUs)
- GPU: NVIDIA consumer Blackwell-class discrete GPU, 16 GiB VRAM, CC 12.0
- Host RAM: ~76 GiB

No hostname, username, personal filesystem paths, SKU model names, or network
identities are recorded.

## Invocation

```text
BTX_RUN_CUDA_DAEMON_LIFECYCLE_TESTS=1 \
BTX_MATMUL_V4_BACKEND=cuda \
  build-cuda/test/functional/test_runner.py feature_matmul_cuda_daemon_lifecycle.py
```

Regtest args follow the Epoch-A atomic tuple used by
`feature_matmul_v47_epoch_a_activation.py` (unified v4/BMX4C/RC at height 6,
DRLT and coupled disabled, Profile 1, production-scale `n=4096`, toy dims off).
A lone `-regtestrcheight` below the default v4/BMX4C/DRLT fixture aborts
construction via `ValidateMatMulAsertParams`.

## Result

| Mode | Result |
| --- | --- |
| foreground | pass |
| `-daemon` | pass |
| `-daemonwait` | pass |

All three modes resolved the same CUDA RC provider identity and completed one
legacy MatMul block mine after RC self-qualification / production-canary
bookkeeping. No forbidden CUDA lifecycle markers
(`cudaSetDevice failed:initialization error`,
`required mining backend not satisfied`,
`CUDA backend fallback to CPU`) were observed.

| Field | Value |
| --- | --- |
| Tip SHA | `c4ac2e439ac496245f12dcbf8b42c9575247dbe9` |
| Resolved provider | `cuda_rc_exact_fused_extract` |
| Device architecture | `sm_120` |
| Driver identity | `13020` |
| Runtime identity | `13030` |
| Canary outcome | `missing_golden` (expected; empty reviewed manifest) |
| Production eligible | false |
| Startup canary passed | false |
| Functional duration | ~6 s (runner wall time for the three modes) |

## Ratification

Unchanged and still false:

- `BTX_MATMUL_NO_INVERSION_GATE_RATIFIED`
- `BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED`

This artifact is engineering evidence that CUDA init survives foreground and
daemon fork modes on Blackwell-class hardware. It is not activation evidence
and does not authorize flipping those gates.


## Audit follow-up (2026-08-01)

Aligned the committed test with the external CUDA daemon lifecycle test audit:

- F01: `-regtestrcheight=101` on the canonical regtest schedule
- F02: removed unsupported `-debug=matmul`
- F03: foreground console capture + early exit while waiting for RPC
- F04: documented explicit `--configfile=build-cuda/test/config.ini`
- F05: assert `backend_runtime.cuda_successes` increases after mining

A retest with the audit-aligned harness is queued behind the in-flight 100-run
hardware campaign.
