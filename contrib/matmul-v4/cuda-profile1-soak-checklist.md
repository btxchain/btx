# CUDA Profile-1 soak — restart / IBD scenario checklist

Pre-ratification operator checklist for `contrib/matmul-v4/cuda-profile1-soak.sh`.
Does not clear roadmap §4 gate 7.

## Before start

- [ ] `rebuild.done` present on GPU host (or binaries current)
- [ ] Status `daemon` / `goldens` / `hwcampaign` / `lifecycle` all `done`
- [ ] `flock` can acquire `/tmp/btx-pr97-campaigns/locks/gpu.lock`
- [ ] `build-cuda/bin/btxd` and `/path/to/btx-cli` executable
- [ ] Evidence stub exists: `doc/evidence/cuda-blackwell-16gib-soak-2026-08-01/README.md`
- [ ] Log dir created: `/tmp/btx-pr97-campaigns/logs/soak/`

## During soak (automated by harness)

- [ ] Cross RC height once; both nodes share tip
- [ ] Periodic relay mines; tips match; `getmininginfo` CUDA provider
- [ ] Competing branch: disconnect → divergent tips → reconnect → converge
- [ ] Restart node B; CUDA canary/provider still CUDA; tip catch-up
- [ ] Cache persistence: mine after restart without CPU GEMM fallback
- [ ] IBD boundary: stop B, mine lag on A, restart B, sync heights

## After soak

- [ ] Copy only sanitized metrics/events/summary into evidence dir (optional)
- [ ] Update evidence README duration / scenarios / PID
- [ ] Set `soak.json` status to `done` or `failed`
- [ ] Leave `ratification: false` and `gate7_claim: false`

## Explicitly not on this checklist

- Multi-day wall clock
- Multi-peer public testnet
- Upgrade-behavior across release binaries
- Ratification / activation constant flips
