# Multi-GPU Profile-1 ExactReplay golden compare — v0.33.3 (Metal half)

Status: **partial corpus**. Metal ExactReplay for the eight canonical Profile-1
production canaries (nonces 1–8, `matmul_dim=4096`) was measured at the
macOS-portable corpus-script freeze below. CUDA has **not** been re-run at this
freeze yet, so `complete_multi_gpu_match` and `cuda_metal_match` are false and
this directory must not populate `CommittedRCProductionGoldenManifest()`.

## Freeze

| | |
|---|---|
| Source revision | `215a73242b2f40d5233b09e0b354a80e23f462d3` |
| Build-relevant tree fingerprint | `54d2b133cb1e155e8a2713c5614bb44046d020f34bbebcc8d6d96543c276b6ee` |
| Episode profile | 1 (Epoch-A consensus shape) |
| Episodes | 8 |
| Canary nonce start | 1 |
| `allow_partial` | true |

The Metal harness was built from a clean checkout of that revision under the
corpus script's fail-closed dirty-tree guard. `embedded_source_revision` equals
`git_tip`, and `embedded_source_dirty` is false.

## Metal result (this directory)

```
cuda_metal_match:         false
complete_multi_gpu_match: false
mismatches:               0
coverage_failures:        0
```

| | Metal |
|---|---|
| Provider | `metal_int8_mpp_tensorops_fused_extract` |
| Architecture class | `m4_class` |
| Device calls | 1'088 |
| Device MACs | 1'129'198'441'725'952 |
| CPU GEMM calls / MACs / fallbacks | 0 / 0 / 0 |
| ExtractMX self-qualification | PASS |
| Harness SHA-256 | `e227fdfdcdf6b8951c0df041b67cd2ee41dbb710c912cf88504da0b14c2104fc` |
| Mean episode wall | 28.1299 s (eight samples; max 28.3377 s) |
| Peak RSS | 6'970'064 KiB |

All eight ExactReplay digests match the previously accepted cohort digests
byte-for-byte. That is expected for a freeze that does not change transcript
code; it is **not** a substitute for a same-revision CUDA reproduction.

## Artifacts

- `multi-gpu-digest-compare.json` — fail-closed partial comparator output
- `raw/profile1-metal-8.json` — Metal harness public-evidence record

Public evidence is machine-class only (no hostname/SKU/path identifiers).

## CUDA half — procedure (not executed here)

The available CUDA system is also a live production attestation authority
(Blackwell-class 16 GiB, sm_120). Running the CUDA golden harness there
requires **explicit owner approval**. This section documents the safe
procedure and the measured costs; it was **not** started in this work.

### Measured costs (prior sm_120 Profile-1 goldens at production dims)

From the last accepted CUDA artifact
(`../multi-gpu-profile1-goldens-cuda-metal-2026-08-04-v0332-final/raw/profile1-cuda-8.json`):

| Metric | Value |
|---|---|
| Per-episode wall | mean **12.058 s**, max **12.107 s** (n=8) |
| Continuous 8-episode batch wall | **~96.5 s** |
| Host peak RSS | **2'532'260 KiB** (~2.41 GiB) |
| Working-set footprint (harness banner) | **~2.82 GiB** |

Read-only observation of the authority GPU while idle between blocks:

| Metric | Value |
|---|---|
| VRAM used by live `btxd` | ~2'979 MiB |
| VRAM free | ~12'872 MiB |
| GPU utilization between blocks | 0 % |
| Block arrival cadence | roughly once per minute |

Memory headroom exists (~13 GiB free vs ~2.8 GiB episode footprint), but
**compute contention** is the real risk: a 12 s ExactReplay episode that
overlaps block validation can delay the authority's own ExactReplay and make
the tip appear to flap to external operators.

### Recommendation

**Do not run the 8-episode batch on the live authority.** Prefer a third-party
sm_120 host (same driver/runtime class) with no consensus duties. If the owner
nonetheless approves an authority-side run, use the single-episode gated
procedure below — never the continuous batch.

### Preferred: third-party sm_120 host

Inputs:

- Clean checkout of freeze `215a73242b2f40d5233b09e0b354a80e23f462d3`
- Build-relevant fingerprint must equal
  `54d2b133cb1e155e8a2713c5614bb44046d020f34bbebcc8d6d96543c276b6ee`
- CUDA build of `matmul-v4-rc-harness` from that exact clean tree

Commands:

```bash
cmake -B build-cuda -DCMAKE_BUILD_TYPE=Release -DBTX_ENABLE_CUDA=ON
cmake --build build-cuda -j "$(nproc)" --target matmul-v4-rc-harness

contrib/matmul-v4/multi-gpu-golden-corpus.sh \
  --harness build-cuda/bin/matmul-v4-rc-harness \
  --backends cuda \
  --episodes 8 \
  --canary-nonce-start 1 \
  --allow-partial \
  --out-dir /path/to/cuda-out
```

Expected outputs:

- `cuda-out/raw/profile1-cuda-8.json` with `embedded_source_revision` =
  `215a7324…`, `embedded_source_dirty=false`, eight digests matching the Metal
  digests in this directory, `provider=cuda_rc_exact_fused_extract`,
  `device_architecture=sm_120`, zero CPU GEMM fallbacks.
- Partial `multi-gpu-digest-compare.json` (cuda-only) with zero coverage
  failures.

Then merge with this Metal half via compare-only (see below).

### Authority-side gated procedure (owner approval required)

Only if a third-party sm_120 host is unavailable and the owner explicitly
approves. Do **not** restart, reconfigure, stop, or redeploy the node.

1. Confirm tip is healthy and GPU is idle (`utilization.gpu == 0`, free VRAM
   ≥ 4 GiB). Record `blocks`/`headers` lag; abort if lag ≥ 1.
2. Build the harness in a **separate tree** at freeze `215a7324…` (do not
   disturb the live datadir or the running binary). The target must be built
   in that isolated tree at this freeze before any episode runs.
3. Run **one episode at a time** (`--episodes 1`, nonce N), at nice/ionice
   idle priority, only while GPU util is 0%:

```bash
nice -n 19 ionice -c3 \
  env BTX_MATMUL_V4_BACKEND=cuda BTX_MATMUL_BACKEND=cuda \
  build-cuda/bin/matmul-v4-rc-harness \
    --base-production --episodes 1 --backend cuda \
    --canary-headers --canary-nonce-start N \
    --emit-frozen-headers --public-evidence \
    --source-revision 215a73242b2f40d5233b09e0b354a80e23f462d3 \
    --out /tmp/cuda-ep-N.json
```

4. Between episodes: re-check tip lag and GPU idle. If lag ≥ 1 header/block or
   util stays elevated, **pause or abort**. Budget ≥ 60 s idle gap after each
   ~12 s episode.
5. After nonces 1–8 succeed, assemble with the corpus script / comparator at
   the same freeze (or feed the eight single-episode records into the normal
   8-episode harness path on a non-authority host). Prefer regenerating a
   single `profile1-cuda-8.json` via the corpus script on a non-authority
   machine when possible so provenance fields stay uniform.

### Compare-only merge (after CUDA raw exists)

Copy `raw/profile1-cuda-8.json` beside `raw/profile1-metal-8.json` in this
directory (or a successor dated directory), then from a clean checkout of the
freeze:

```bash
contrib/matmul-v4/multi-gpu-golden-corpus.sh \
  --compare-only \
  --backends cuda,metal \
  --episodes 8 \
  --canary-nonce-start 1 \
  --out-dir doc/evidence/multi-gpu-profile1-goldens-cuda-metal-2026-08-12-v0333
```

Success requires `complete_multi_gpu_match=true`, `cuda_metal_match=true`,
`allow_partial=false`, zero mismatches/coverage failures, and
`tip_sha`/`source_tree_fingerprint` equal to the freeze above.

## What must be re-sealed after both halves exist

`verify-production-golden-seal.py seal` fails today because the committed
manifest still points at the older v0.33.2 corpus whose `tip_sha` no longer
matches the post-merge freeze. Do **not** hand-edit evidence JSON.

Once compare-only reports a complete CUDA+Metal match at freeze
`215a7324…` / fingerprint `54d2b133…`:

1. Keep that freeze commit as the measured revision (harness build + both
   provider runs). Doc-only evidence commits after the freeze are fine; they
   must not change `CMakeLists.txt`, `cmake/`, `src/`, or `contrib/matmul-v4/`.
2. Update
   `src/matmul/matmul_v4_rc_production_golden_manifest.data` **only** in a
   subsequent seal commit so that each row carries:
   - `source_revision` = `215a73242b2f40d5233b09e0b354a80e23f462d3`
   - `source_tree_fingerprint` = `54d2b133cb1e155e8a2713c5614bb44046d020f34bbebcc8d6d96543c276b6ee`
   - `evidence_path` = this corpus directory (or the final combined directory)
   - digests and per-provider `harness_sha256` taken from the real raw artifacts
3. Seal commit may change the manifest and `doc/` only. Build-relevant diff
   from freeze → seal HEAD must be exactly the manifest file.
4. Recompute the fingerprint recipe to confirm the fixed point:

```bash
EXCL='src/matmul/matmul_v4_rc_production_golden_manifest.data'
git ls-tree -r --full-tree HEAD -- CMakeLists.txt cmake src contrib/matmul-v4 \
  | grep -v "	${EXCL}$" | sha256sum
```

5. Run `python3 contrib/matmul-v4/verify-production-golden-seal.py seal --root .`
   and require PASS.

A portability fix under `contrib/matmul-v4` already moved the freeze to
`215a7324…`. Prematurely rewriting the manifest before the CUDA half exists
cannot make `seal` pass (`complete_multi_gpu_match` must be true).
