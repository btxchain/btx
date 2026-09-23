# BTX 0.34.9 — Registry independence, host / load / generate

**Status:** **shipping**. `CLIENT_VERSION` is **0.34.9** with
`CLIENT_VERSION_RC=0` and `CLIENT_VERSION_IS_RELEASE=true`. GitHub tag
**v0.34.9**. Not a consensus change relative to 0.34.8.

This is the 0.34.8 monetary baseline plus origin-independent fetch, `.btx` /
`btx://` retrieve, checkout, optional GPU load, host-profile local generate,
assumeutxo persist (#163), ExactReplay CPU confirmation on strict-device
mismatch, and on-chain bounty / release-campaign timelock spends.

People: [HUMANS.md](../../HUMANS.md),
[doc/modelnet/end-to-end.md](../modelnet/end-to-end.md).
Agents: [AGENTS.md](../../AGENTS.md).
RPC: [doc/modelnet/rpc.md](../modelnet/rpc.md).

## What this release is (and is not)

- **No consensus / ASERT / header-PoW / issuance change.**
- **`automatic_spend_atoms` stays 0.**
- **No remote inference marketplace.** Local use is the end of acquisition.
- Helper `approvebountyaward` is policy, not settlement.
- Tester tags `v0.34.9-dev.pr198` and `v0.34.9-dev.pr198.2` stay in place;
  they are not recut. Historical `v0.34.8-rc*` tags stay in place.

A node with **no** pin membership, **no** attestor key, and **no**
trusted-mirror pin must still reach tip from ExactReplay alone.

## Precompiled archives

Archives are **0.34.9** (`IS_RELEASE=true`). `btxd -version` prints
`v0.34.9`. P2P subversion is `/BTX:0.34.9/`. Packaged `bin/btxd` is a
`#!/bin/sh` wrapper; gate the real binary with
`python3 scripts/release/verify_release_btxd.py` on `libexec/btxd.real`.

Every flavor is configured `-DWITH_ZMQ=ON -DWITH_MODELNET=ON` and ships the
sibling helpers `btx-modeld`, `btx-modelcheck`, `btx-open`, `btx-hcpd`,
`btx-hosted`, `btx-capability`, `btx-capabilityd` when present. Metal
archives include precompiled `*.metallib` next to `libexec/btxd.real`.

| Platform id | Archive | Notes |
|---|---|---|
| `linux-x86_64` | `btx-0.34.9-x86_64-linux-gnu.tar.gz` | GCC 13 Release, CPU MatMul |
| `linux-x86_64-cuda12` | `btx-0.34.9-x86_64-linux-gnu-cuda12.tar.gz` | CUDA 12.9, Blackwell `sm_120` class. Static cudart + bundled `libcublasLt` |
| `linux-x86_64-cuda13` | `btx-0.34.9-x86_64-linux-gnu-cuda13.tar.gz` | CUDA 13.3, Blackwell `sm_120` class. Static cudart + bundled `libcublasLt` |
| `macos-arm64-metal` | `btx-0.34.9-arm64-apple-darwin.tar.gz` | Apple Silicon Metal, Homebrew-free Mach-O, precompiled metallibs |

Published Linux archives need **GLIBC_2.38** / **GLIBCXX_3.4.32** and
**OpenSSL ≥ 3.5** (ML-KEM-768) for the model plane. The wrappers prepend
`lib/` when `libssl.so.3` is bundled. The published CUDA 12/13 fatbins are
**Blackwell-only**; Ampere/Ada/Hopper operators use the CPU archive or a
source build.

GPU ExactReplay goldens were **not** re-run on a live attestor GPU for this
cut. CPU ExactReplay remains the portable confirmation oracle (see below).

## What landed

| Surface | What to expect |
|---|---|
| **Registry independence** | Origins are disposable. `btx://` + `VerifiedManifest` is identity. Hugging Face / ModelScope / local disk are origins, not catalogues of record. |
| **Host / share / retrieve** | `hostmodel` demand-seeds. `.btx` is a JSON magnet analog. `getmodel` accepts a `.btx` path or `btx://`. Unix `getmodel` is async (`status=running` + `job_id`). |
| **Checkout** | `exportmodelpath` rebuilds files under `checkout/<artifact>/` and hardlinks from `source_path` when SHA-384 still matches. |
| **Load** | `loadmodel` inventories SafeTensors. Optional `BTX_MODEL_CUDA_LOADER --hold --smoke` keeps tensors resident. `unloadmodel` SIGTERMs that child only. |
| **Generate** | `generatemodel` / `getmodelhostprofile`. Unknown arch / pickle / missing adapter fail closed. CUDA smoke is **not** generate. |
| **Bounties / rewards / WRC** | Mining coinbase funds the lots. Completion is an on-chain two-leaf P2MR spend: council CLTV after `award_height`, contributor `refund()` after `refund_height`, or staged SHA-256 `preparebountyclaim` via local `secret_ref`. Release-campaign / wBTX reuses `htlc_sha256` + `buildhtlcclaim` / `buildhtlcrefund`. |
| **Assumeutxo persist (#163)** | Pre-attestation historical hole bodies on the background chainstate can persist without GETMMATTEST. |
| **ExactReplay CPU oracle** | Strict-device CUDA mismatch is confirmed by portable CPU ExactReplay (`InvalidConsensus` or recovered header). |

Protocol: [registry-independence.md](../modelnet/registry-independence.md).
Copy-paste: [end-to-end.md](../modelnet/end-to-end.md).
Generate: [generate.md](../modelnet/generate.md).
Linux matrix: [linux-release-builds.md](../linux-release-builds.md).
