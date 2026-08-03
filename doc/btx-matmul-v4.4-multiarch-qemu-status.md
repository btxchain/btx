> **HISTORICAL DESIGN / AUDIT EVIDENCE — MatMul v4.7 roadmap takes precedence.**
> This document preserves version-local findings, names, and measurements; it is not
> the current activation plan. The proposed transition is defined by
> `doc/btx-matmul-v4.7-transition-roadmap.md`: Epoch A uses Profile 1 with
> ExactReplay authority and optional shadow proofs; Epoch B requires both a durable
> Profile-1 proof and ExactReplay; Epoch C makes the Profile-1 proof authoritative;
> and Epoch D separately moves to Profile 2 under proof authority. Mainnet Epoch A (v4 = BMX4C = RC) now activates at height 182'600; all other transition heights remain disabled. Any older “production,” “default,” “shipping,” direct-fork,
> sampled-verifier, or coupled-profile recommendation below is historical unless the
> canonical roadmap expressly carries it forward.

# Multi-arch QEMU status note (Agent E)

**Do not treat this as a PASS.** Updated from live `/tmp/btx_val_matrix` monitors.

| Platform | Image / path | Status | Notes |
|---|---|---|---|
| `linux/amd64` | `btx-matmul-test:linux_amd64` via Ubuntu `Dockerfile.tests` | **PASS** (2026-07-19) | `matmul*` 550 cases, 0 errors |
| `linux/arm64` | QEMU buildx Ubuntu 24.04 | **FAIL (build)** (snapshot 2026-07-19T14:33+09) | QEMU SIGSEGV (Error 139) compiling leveldb under qemu-aarch64 (`FAIL_qemu_sigsegv`); **not** a matmul* PASS |
| `linux/riscv64` | QEMU buildx Ubuntu 24.04 | **BUILDING** (snapshot 2026-07-19T14:33+09) | ~75% — `test_btx` PQ suites under qemu-riscv64-static |

Canonical recipe (repo):

```bash
docker buildx build --platform linux/amd64 \
  -f contrib/docker/Dockerfile.tests -t btx-test:amd64 --load .
docker run --rm btx-test:amd64 --run_test='matmul*'

docker buildx build --platform linux/arm64 --build-arg JOBS=8 \
  -f contrib/docker/Dockerfile.tests -t btx-test:arm64 --load .
docker run --rm --platform linux/arm64 btx-test:arm64 --run_test='matmul*'

docker buildx build --platform linux/riscv64 --build-arg JOBS=8 \
  -f contrib/docker/Dockerfile.tests -t btx-test:riscv64 --load .
docker run --rm --platform linux/riscv64 btx-test:riscv64 --run_test='matmul*'
```

Monitor existing lanes:

```bash
tail -f /tmp/btx_val_matrix/logs/lane_e_docker_arm64_wrap.log
tail -f /tmp/btx_val_matrix/logs/lane_f_docker_riscv_wrap.log
```

When a lane finishes, update this table to PASS/FAIL with the log path — never invent PASS.
