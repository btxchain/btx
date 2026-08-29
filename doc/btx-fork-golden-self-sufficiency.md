# Fork self-sufficiency for ExactReplay goldens

0.34 treats the production golden manifest as a **local comparison
corpus**, not as a network blessing and not as a permission list run by
the original maintainers. A fork or operator does **not** need a row in
this repository's manifest, and does **not** need to mint a row of their
own, for hardware that passes the runtime self-test.

## What ExactReplay is

Consensus is `CheckMatMulProofOfWork_RC` / ExactReplay on **this node**.
A block is valid because this node recomputed it, not because a golden
JSON exists in our tree. The canary / sealed corpus is optional
comparison against a known row. It is not a consensus rule, and it is
not a hardware-approval registry.

## What actually admits mining

METAL is admissible if and only if `IsLtTensorOpsGemmAvailable()` — the
byte-exact TensorOps self-test that builds INT8 operands, computes
`ExactGemmS8S8` on CPU, runs the same on GPU, and fails closed unless
the results are byte-identical. CUDA, HIP, and Ascend have the same
shape of fail-closed ExactGemm self-qualification. Device-name class
(`m4_class` / `m5_class`) is reporting and golden-row selection, not
this gate (`src/matmul/backend_capabilities_v4.h`).

That self-test is device-agnostic and cannot be faked by a manifest
row. Floating-point-only paths remain inadmissible. Blocks this node
produces are still ExactReplayed and fully validated by every peer.

## Manifest rows are comparison, not permission

- **No matching row** (M5 today, or any future class): mining admission
  proceeds from self-qualification. `getmininginfo` reports
  `admission_path=self_qualification`. `missing_golden` is a reporting
  condition, not a refusal.
- **Matching row, digest agrees**: `admission_path=reviewed_golden`.
- **Matching row, digest disagrees**: fail closed. That is a real
  correctness failure, not an absent blessing.

Do not open a PR against this repository whose purpose is “please bless
our golden.” That would re-centralize mining admission in whoever
merges the row.

## What this tree will not do

- It will not add an `m5_class` row on behalf of the community. An M5
  that passes TensorOps is already admissible; minting a row here would
  restore the permission model this document rejects.
- It will not accept goldens measured on hardware that failed the
  TensorOps self-test and then treat that as a classification fix.
  Classification (capability) and the manifest row (measured class)
  are different questions.

## What stays in this repository

The CUDA `sm_120` and Metal `m4_class` cohort this line measured, the
seal scripts, and
[`btx-matmul-v4.7-production-golden-policy.md`](btx-matmul-v4.7-production-golden-policy.md)
describe how **this** line records **this** binary's comparison corpus.
Forks may copy the scripts and optionally record their own rows for
telemetry. They do not send the JSON back, and they do not need a row
to mine.

## Optionally record a comparison row

A builder who wants a reviewed digest to compare against on restart may
still measure one. On the machine that has the device, at freeze commit
`F` with fingerprint `FP(F)`:

```bash
contrib/matmul-v4/multi-gpu-golden-corpus.sh \
  --harness build-metal/bin/matmul-v4-rc-harness \
  --backends metal \
  --source-revision "$F" \
  --source-tree-fingerprint "$FP" \
  --out-dir doc/evidence/multi-gpu-profile1-goldens-metal-$(date +%Y%m%d)
```

Then add one line to `src/matmul/matmul_v4_rc_production_golden_manifest.data`
for that class (`m5_class`, `m4_class`, …), commit the evidence plus the
`.data` file, and run:

```bash
python3 contrib/matmul-v4/verify-production-golden-seal.py seal --root .
python3 contrib/matmul-v4/verify-evidence-provenance.py --strict
```

This is optional comparison. It is not required for mining admission.
Do not open a PR against this repository whose purpose is “please bless
our golden.”
