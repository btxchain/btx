# Fork self-sufficiency for ExactReplay goldens

0.34 treats the production golden manifest as a **local mining-admission
belt**, not as a network blessing and not as a submission process run by
the original maintainers.

## What ExactReplay is

Consensus is `CheckMatMulProofOfWork_RC` / ExactReplay on **this node**.
A block is valid because this node recomputed it, not because a golden
JSON exists in our tree. The canary / sealed corpus is a local gate so
that *this binary* refuses to **mine** on a backend it has not measured.
It is not a consensus rule, and it is not a hardware-approval registry.

## What a fork does

A fork that wants to admit a new mining backend (a new CUDA `sm_*` row,
a Metal `m5_class` row, HIP, …) adds that row to **its**
`src/matmul/matmul_v4_rc_production_golden_manifest.data`, rebuilds, and
reseals against **its** freeze. Other nodes on the same consensus rules
ExactReplay the resulting blocks regardless of whose manifest produced
them.

Do not open a PR against this repository whose purpose is “please bless
our golden.” That would re-centralize mining admission in whoever merges
the row. Fork, measure, ship.

## What this tree will not do

- It will not add an `m5_class` row on behalf of the community. Metal
  admission is the TensorOps self-test; the golden row is selected by
  the reported class (`ClassifyFromDeviceName`). This tree ships CUDA
  `sm_120`. A Metal miner adds **their** class row to **their**
  manifest. That is how easyNode ships M5 mining today.
- It will not accept goldens measured on hardware that failed the
  TensorOps self-test and then treat that as a classification fix.
  Classification (capability) and the manifest row (measured class)
  are different questions; mixing them is how an M5 self-quals and
  then dies on `canary=missing_golden` (MendeMatthias, 2026-08-26,
  PR 123). Adding the row in **your** freeze is the fix.

## What stays in this repository

The CUDA `sm_120` cohort this line measured, the seal scripts, and
[`btx-matmul-v4.7-production-golden-policy.md`](btx-matmul-v4.7-production-golden-policy.md)
describe how **this** line reseals **this** binary. Forks copy the
scripts; they do not send the JSON back.

## Add a Metal (or HIP) row in four minutes

On the machine that has the device, at **your** freeze commit `F` with
fingerprint `FP(F)`:

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

Do not open a PR against this repository whose purpose is “please bless
our golden.”

