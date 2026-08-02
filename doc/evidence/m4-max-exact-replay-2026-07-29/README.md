# M4 Max Profile 1 ExactReplay Metal baseline

This directory records the preliminary Profile 1 production-dimension
ExactReplay runs from the unpublished `agent/metal-exact-replay` branch.
Profile 1 is now the proposed MatMul v4.7 Epoch-A workload, but the corrected
100-run campaign in `../m4-max-profile1-loaded-2026-07-30/` supersedes this
single-run baseline for launch review. The Profile 2 measurement in
`../m4-max-exact-replay-profile2-2026-07-30/` is later-epoch diagnostic
evidence, not an Epoch-A gate. All activation heights remained disabled.
Transition authority and gate precedence follow the
[`MatMul v4.7 roadmap`](../../btx-matmul-v4.7-transition-roadmap.md).

## Full-Metal Profile 1 baseline

- Source revision: `903b74985d640d1194d5bc54247dc5263207aa74`
- PR base: public PR 95 head `43411dda8468236cd10b2441832511df34e94193`
- Host: Mac Studio, Apple M4 Max, 32 GPU cores, 36 GB unified memory
- Backend: Metal 4 MPP INT8 tensor operations
- Report: `rc-production-r4-full-metal.json`

```sh
BTX_RC_ACCEL_POLICY=portable \
  ./build-metal/bin/matmul-v4-rc-harness \
  --production \
  --episodes 1 \
  --backend metal \
  --source-revision 903b74985d \
  --out doc/evidence/m4-max-exact-replay-2026-07-29/rc-production-r4-full-metal.json
```

The four-round Profile 1 episode completed in **28.359847 seconds**:

- Phase 1: 0.498479 seconds
- Phase 2: 27.121650 seconds
- Phase 3: 0.739698 seconds
- Peak resident memory: 6,964,000 KiB
- Consensus MACs on Metal: 141,149,805,215,744 of 141,149,805,215,744
- Operand XOF calls on Metal: 144
- Resident 16-layer FFN-chain calls on Metal: 4
- Merkle rounds on Metal: 4
- CPU calls and fallbacks: 0
- Episode digest:
  `3099acef550dd8c3c0112fb7c19378269abee56a2828fac7283567a269bffe5c`

The strict `full_metal_pipeline` gate requires device-side operand XOF,
dequantization, every consensus contraction, both ExtractMX stages, the
resident FFN chain, Merkle leaf construction, and Merkle subtree folding. A
missing callback or any CPU contraction fallback fails an explicit Metal run.

A separate three-episode run measured 28.263500 seconds mean wall time and
0.56% coefficient of variation. The later dimension-bound 100-run p99,
back-to-back consensus-worker, and reorg/cancellation evidence is recorded in
`../m4-max-profile1-loaded-2026-07-30/`. Cross-machine parity remains launch
acceptance work.

This is not evidence that the eight-round Profile 2 workload fits a 90-second
block interval. Consensus activation remains disabled
(`nMatMulRCHeight=INT32_MAX`).

## Original contraction-only baseline

### Frozen source

- Source revision: `e440314d77e9535d194c8c9c09386836258123ae`
- PR base: public PR 95 head `43411dda8468236cd10b2441832511df34e94193`
- Host: Mac Studio, Apple M4 Max, 32 GPU cores, 36 GB unified memory
- Backend: Metal 4 MPP INT8 tensor operations with fused on-device ExtractMX

### Command

```sh
BTX_RC_ACCEL_POLICY=portable \
  ./build-metal/bin/matmul-v4-rc-harness \
  --production \
  --episodes 1 \
  --backend metal \
  --source-revision e440314d77e9535d194c8c9c09386836258123ae \
  --out doc/evidence/m4-max-exact-replay-2026-07-29/rc-production-r4-metal.json
```

An explicit `--backend metal` makes device execution mandatory: a missing
device, failed qualification, or CPU fallback fails the run.

### Result

- Four-round production episode: 62.623491208 seconds
- 90-second target margin: 27.376508792 seconds
- Peak resident memory: 3,792,800 KiB
- Consensus MACs on Metal: 141,149,805,215,744 of 141,149,805,215,744
- Device calls: 136
- CPU calls and fallbacks: 0
- Phase 1 and Phase 2 ExtractMX: on device
- Episode digest:
  `3099acef550dd8c3c0112fb7c19378269abee56a2828fac7283567a269bffe5c`

The measured result qualifies the frozen Profile 1 ExactReplay baseline on this
M4 Max. It does not qualify Profile 2, native OCP MXFP4, M5 identity, or
cross-host execution.
All consensus matrix contractions and ExtractMX work are on Metal; operand XOF,
Merkle hashing, and final committed-output staging remain on the host, so the
report deliberately records `device_resident: false`.

Consensus activation remains disabled (`nMatMulRCHeight=INT32_MAX`). The
evidence establishes local launch viability, not permission to activate without
the remaining cross-host campaign.

## Provenance status

`rc-production-r4-metal.json` declares `source_revision
e440314d77e9535d194c8c9c09386836258123ae` and `rc-production-r4-full-metal.json`
declares `903b74985d`; neither resolves to a commit in this repository, so the
code state that produced these numbers cannot be established here. They are
retained as historical measurements and are not admissible as production-golden
evidence. `contrib/matmul-v4/verify-evidence-provenance.py` fails on both until
they are regenerated under the current provenance rules.
