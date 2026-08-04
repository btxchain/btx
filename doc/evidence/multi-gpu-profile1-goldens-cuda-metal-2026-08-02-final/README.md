# Historical CUDA + Metal Profile-1 golden corpus (`602a9d08…`)

Status: **internally complete for source revision `602a9d08…`, but stale for
the current activation candidate. Metal has since been rerun from the current
code freeze; a matching CUDA rerun remains pending.** The recorded comparison remains
`complete_multi_gpu_match: true` with 0 mismatches and 0 coverage failures for
its historical source revision.

## Policy

Independent reproduction for Epoch-A production goldens is **cross-GPU-backend**
(CUDA and Metal) ExactReplay on identical frozen canary headers. HIP is an
optional provider whose submitted evidence must also match. Portable CPU oracle
reproduction is not required for this GPU-optimized chain.

## Provenance

Both providers are bound to the same reviewed code freeze:

- `source_revision` `a0d441e1f1ab5376cd98b0d7effe1506cf2cfed1`
- `source_tree_fingerprint`
  `4649ffd436459622ea2be55fa34c0ee4877ee8c69760db5f21d6f805f2e98483`
  (`git ls-tree -r --full-tree <rev> -- CMakeLists.txt cmake src | sha256sum`)

The fingerprint was recomputed independently on the CUDA host and on a second
machine before the run. Subsequent commits changed build-relevant files under
`src/` (including consensus parameters, production-canary gating, networking,
and validation). The branch tip therefore no longer has this fingerprint and
is not equivalent under the rule in
`doc/btx-matmul-v4.7-production-golden-policy.md`. Later fixes may be
digest-neutral, but the policy intentionally does not infer that from a code
review: changing any covered build-relevant file requires new provider runs.

Harness binaries differ per provider, as expected:

| provider | `harness_sha256` |
| --- | --- |
| cuda | `e50e08ca1e19e539063250d28e9b563163f9e4656926f9961b824f535ad28df4` |
| metal | `8bd1c7438a23b79f6aa05644390d6cb4e8d000f0fa214d1116d1b62f146dff7f` |

## Historical result

Eight canonical 182-byte production canary headers, nonces 1 through 8,
`matmul_dim=4096`. All eight ExactReplay digests are byte-identical across the
two providers, as are the frozen header bytes:

```
nonce 1  b4777985d4f2621d0b9c119f4188ac7d80158fc92560ade96cc7a3fd8cfae953
nonce 2  d5ca4a68a259c6494128993d752104e6ec4ddf9551e5bc1ee2aeb61dc60264aa
nonce 3  d95d122ad36c749e4a71e6aa449e566c2e0cd5c6d59105b7324d2aaeb063bf7f
nonce 4  0fd1b4a52c59fabf035b6c47f4c87be01f2eaa7b4834eb9e8bd7dd93b28766c7
nonce 5  197d83c30a8090be3ad881c3baf423790c7dffeb529470e384f4712fc1c7853f
nonce 6  dd73fd8532f72659dc75fe38a6623fbde07f7dcfb24c02a32837b67885402698
nonce 7  b85b555946eaa351666044aed7a57724b8e3a694d7e27f50f21d44f6f566140b
nonce 8  5a9041c96f0adeb5bba90d01ae88f4919fd708d41613361b3d3e12d9aea8415a
```

Both providers independently report 1,088 device calls and
1,129,198,441,725,952 device MACs, with zero CPU GEMM calls, zero CPU MACs, and
zero fallbacks. CUDA ran on Blackwell-class `sm_120` (strict
`cuda_rc_exact_fused_extract`, `fully_accelerated=true`, ExtractMX self-qual
PASS, `episode_cv` 0.0046, mean phase wall 32.61 s); Metal ran on M4-class
Apple silicon (mean 28.08 s).

## What this does and does not establish

It demonstrates a matching CUDA and Metal corpus for revision `602a9d08…`.
It does **not** close the exact-final-tree production-golden requirement, does
not authorize activation, and must not populate
`CommittedRCProductionGoldenManifest()` — that vector is deliberately still
empty. After all build-relevant fixes settle, the same eight canonical headers
must be rerun on strict CUDA and strict Metal builds from one exact final
revision/fingerprint, compared with zero coverage failures, and passed through
the strict provenance and privacy gates. Populating the manifest additionally
requires the provider-bound ASERT calibration and complete lifecycle campaigns
to be reviewed, and remains a separate consensus-visible commit. Public RC
heights stay `INT32_MAX`, and both ratification gates stay false.

Two providers agreeing also does not prove the absence of a common
specification bug; the portable oracle remains the dispute tool.

## Reproducing the historical result

```
contrib/matmul-v4/multi-gpu-golden-corpus.sh \
  --harness <build>/bin/matmul-v4-rc-harness \
  --backends cuda \
  --episodes 8 --canary-nonce-start 1 \
  --out-dir <scratch> \
  --source-revision a0d441e1f1ab5376cd98b0d7effe1506cf2cfed1 \
  --source-tree-fingerprint 4649ffd436459622ea2be55fa34c0ee4877ee8c69760db5f21d6f805f2e98483
```

Then place both providers' `raw/profile1-<backend>-8.json` in one directory and
re-run with `--compare-only`. `contrib/matmul-v4/verify-evidence-provenance.py`
cross-checks the recorded revision and fingerprint against this repository and
must pass before the manifest is populated.

## Artifacts

- `raw/profile1-cuda-8.json`, `raw/profile1-metal-8.json` — public-evidence
  harness results.
- `multi-gpu-digest-compare.json` — the complete cross-provider comparison.

The artifacts expose machine-class and provider/runtime capability data only.
They contain no hostname, account name, filesystem path, device serial, network
address, credential, or deployment secret;
`contrib/matmul-v4/check-public-evidence.py` passes on both.
