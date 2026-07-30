# PR #89 Workstream F — Adversarial review checklist

Bundled with substantive test/gate changes on `pr89-ws-F-tests`.
Historical PR89 checklist, retained for provenance. The MatMul v4.7 roadmap is
`doc/btx-matmul-v4.7-transition-roadmap.md`. This is not an activation
decision; every epoch height remains disabled and unfinished proof arbiters are
OFF.

## Consensus safety

- [ ] `nMatMulRCHeight` / `nMatMulRCCoupledHeight` still `INT32_MAX` on public params
- [ ] Epoch A selects Profile 1; complete ExactReplay is sole consensus accept
- [ ] Epoch B–D heights remain disabled; no proof or Profile-2 authority leaks
- [ ] Mandatory proof carriage is canonical/durable, never sidecar-only
- [ ] GKR/sampled/Freivalds arbiters default OFF
- [ ] Three-axis schedule / full-bank / material-exchange parked OFF
- [ ] `getenv` cannot flip consensus digests (`rc_dc_getenv_*`, hetero ExactGemm/GKR env)
- [ ] Golden digests pinned; silent replacement forbidden — require transcript/version bump

## Episode / Q-batch

- [x] CPU stub `RunBarrierGraph` → `graph_unavailable` (not BindEpisode)
- [x] CUDA without `BindEpisode` → BindEpisode required
- [ ] WS-A: seeded Q>1 after `SetDeterministicMatMulSeeds` batch == per-header oracle
  - Soft-skipped on base tip (`rc_dc_seeded_q_window_batch_matches_oracle`)
- [ ] Resident graph: no per-GEMM H2D/D2H/synchronize (WS-C)
- [ ] Device fault / winner reseal paths (WS-C/D)

## Acceleration honesty

- [ ] MXFP4 native latch only after byte-exact self-qual (WS-B)
- [ ] Scalar-decode never labeled `native_mxfp4_qualified` (gate tests cover refuse)
- [ ] Provider claims match executed backends; unavailable HW not marked complete (WS-E)

## Gate / evidence (fail closed)

- [x] Empty / missing campaign evidence → PARTIAL/NO-GO, never GO
- [x] Dirty `source_revision` → never GO
- [x] Fabricated projection / MAC / simulated interconnect → never GO
- [x] Hardware identity (`device_id`, `host_cpu`) bound into report rows
- [x] Telemetry schema_version=3 fields agree with emit contract; telemetry ≠ certification
- [ ] No B200/MI355X/etc. evidence fabricated when silicon absent

## CI / local

- [ ] `matmul_v4_rc_*` + `matmul_v4_lt_*` green on CPU build
- [ ] `python3 contrib/matmul-v4/test_rc_gate.py` green
- [ ] Sanitizer/fuzz opportunistic only — do not block merge on missing ASAN lane

## Root merge notes

1. Integrate F last conceptually after A→B→C→E→D.
2. After WS-A lands, re-run `rc_dc_seeded_q_window_batch_matches_oracle` — soft-skip must become hard pass.
3. Never raise heights from offline GO tallies.
4. Never collapse Epochs A–D into one activation height.
