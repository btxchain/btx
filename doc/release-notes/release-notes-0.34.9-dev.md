# BTX 0.34.9-dev — Registry Independence, host / load / generate

**Status:** development snapshot for
[PR 198](https://github.com/btxchain/btx/pull/198).
`CLIENT_VERSION` is **0.34.9** with `CLIENT_VERSION_IS_RELEASE=false`.
This is **not** a shipping tag and **not** a consensus change.

Use it to exercise origin-independent fetch, `.btx` / `btx://` retrieve,
checkout, optional GPU load, host-profile local generate, assumeutxo persist
(#163), and the `btx-model` agent door. Do not treat it as `v0.34.8` or as
production-ready.

## Linux x86_64 CPU archive

Published GitHub prerelease tag: **`v0.34.9-dev.pr198.2`** (follow-up to
`v0.34.9-dev.pr198`; both are prereleases, not `--latest`).

| Asset | Notes |
|---|---|
| `btx-0.34.9-dev.pr198.2-x86_64-linux-gnu.tar.gz` | CPU node + model helpers from this branch |
| `SHA256SUMS` | Unsigned checksums for this snapshot |
| `btx-release-manifest.json` | Platform map for `btx-agent-setup.py` |

This host-built archive is **GLIBC_2.38 / GLIBCXX_3.4.32**. The **model plane**
also needs **OpenSSL ≥ 3.5** (ML-KEM-768). Debian 13 and Ubuntu 25.10 work.
Ubuntu 24.04 (OpenSSL 3.0) cannot load `btxd.real` / `btx-modeld.real` unless
the archive's `lib/libssl.so.3` + `lib/libcrypto.so.3` are present (the
`bin/*` wrappers prepend `lib/` to `LD_LIBRARY_PATH`). Missing `libgomp1` is
called out by the wrapper. `btx-modeld` fail-closed on missing ML-KEM exits
**2**. CUDA and macOS archives are not part of this snapshot.

Unpack, then:

```
tar -xzf btx-0.34.9-dev.pr198.2-x86_64-linux-gnu.tar.gz
cd btx-0.34.9-dev.pr198.2
./bin/btxd -version
python3 contrib/modelnet/btx-model --help
```

`bin/btxd` is a wrapper. The ELF is `libexec/btxd.real`. Gate it with
`python3 scripts/release/verify_release_btxd.py --archive …` if you rebuild.

## What landed on this branch

| Surface | What to expect |
|---|---|
| **Registry independence** | Origins are disposable. `btx://` + `VerifiedManifest` is identity. Hugging Face / ModelScope / local disk are origins, not catalogues of record. |
| **Host / share / retrieve** | `hostmodel` demand-seeds. `.btx` is a JSON magnet analog (not hashed as weights). `getmodel` accepts a `.btx` path or `btx://`. Unix `getmodel` is async (`status=running` + `job_id`). |
| **Checkout** | `exportmodelpath` rebuilds files under `checkout/<artifact>/` and hardlinks from `source_path` when SHA-384 still matches. |
| **Load** | `loadmodel` inventories SafeTensors. Optional `BTX_MODEL_CUDA_LOADER --hold --smoke` keeps tensors resident. `unloadmodel` SIGTERMs that child only. Never a network inference server. |
| **Generate** | `generatemodel` / `getmodelhostprofile`: GGUF + `BTX_LLAMA_CLI`, or allowlisted SafeTensors + `BTX_MODEL_GENERATE`. Unknown arch / pickle / missing adapter fail closed. CUDA smoke is **not** generate. [generate.md](../modelnet/generate.md). |
| **Bounties / rewards / WRC** | Mining coinbase funds the lots. Bounty complete is an on-chain two-leaf P2MR spend: council CLTV after `award_height`, contributor `refund()` after `refund_height`, or staged SHA-256 `preparebountyclaim` via local `secret_ref`. Release-campaign / wBTX reuses `htlc_sha256` + `buildhtlcclaim` / `buildhtlcrefund`; mempool rejects refunds until locktime. Helper `approvebountyaward` is not a spend. Proofs: `feature_modelnet_bounty_lifecycle.py`, `wallet_modelnet_funding.py`, `wallet_htlc_atomicswap.py`. |
| **Assumeutxo persist (#163)** | Pre-attestation historical hole bodies on the background chainstate can persist without GETMMATTEST. Issue **#163** is closed. |
| **ExactReplay CPU oracle** | 0.34.8 strict-device CUDA left a digest mismatch retryable when no second GPU existed. 0.34.9 restores the 0.34.7 portable CPU ExactReplay confirmation: CUDA/Metal still serve honest headers; on mismatch, CPU ExactReplay confirms `InvalidConsensus` or recovers the header. CPU and device-oracle toy episodes must produce the same digest. |

`automatic_spend_atoms` stays **0**. `execution_profile` stays **0**
(unqualified). `trust_remote_code` stays **false**. `inference=false` and
`remote_inference=false` on load/generate.

## What to test

- Walletless model import: `wallet_required=false`,
  `publisher_must_republish=false`, `automatic_spend_atoms=0`.
- `origins[]` on an import plan, including Hugging Face, ModelScope, and
  other allow-listed hubs as **origins**, not identities.
- `btx-model --json fetch|resolve|verify|modelpack`.
- Live WAN HTTPS is **fail-closed** unless you set `live_wan` /
  `BTX_MODELNET_LIVE_WAN=1`. When enabled, the client follows at most three
  re-gated `https` CDN redirects and reports `origin_errors` per origin.
  Recipe: `contrib/modelnet/recipes/registry-live-wan-hf-config.json`.
- LOCAL import may omit `files[]`; `piece_origins` records `"local"`; a
  second import of the same bytes is idempotent.
- Leafless multi-origin mix without `piece_sha384_hex` must fail closed.
- Host → share `.btx` / `btx://` → retrieve `FREE_ONLY` → `exportmodelpath`
  checkout (hardlink when hashes match).
- `loadmodel` with `BTX_MODEL_CUDA_LOADER` set; `unloadmodel` must not
  touch production `btxd`.
- `getmodelhostprofile` then `generatemodel` on a complete replica that
  matches this host. Unknown architecture / pickle must fail closed.
  Missing adapter / llama-cli is `NOT_RUN`, not a fake PASS.
- Create → find → on-chain complete a bounty on isolated regtest (owned
  helper, `-modelbind=off`): `feature_modelnet_bounty_lifecycle.py --descriptors`.
  Funding is a two-leaf P2MR output. Completion is
  `preparebountyaward` after `award_height`, `preparebountyrefund` after
  `refund_height`, or staged `preparebountyclaim` with a local `secret_ref`.
  Helper `approvebountyaward` is not a spend. Release-campaign / wBTX HTLC
  fund/claim/refund: `wallet_modelnet_funding.py --descriptors` and
  `wallet_htlc_atomicswap.py --descriptors`. Lots are funded from mature
  coinbase (mining rewards).

Protocol: [registry-independence.md](../modelnet/registry-independence.md).
Copy-paste use: [end-to-end.md](../modelnet/end-to-end.md).
Generate: [generate.md](../modelnet/generate.md).
Agent recipes: [agent-recipes.md](../modelnet/agent-recipes.md).

## What this is not

- Not `--latest`. Leave current shipping / rc tags alone.
- Not a recut of `v0.34.8`.
- Not signed Guix. Treat binaries as a convenience for testers of PR 198.
- Not CUDA. Not macOS. Not Windows. The CPU archive does not include a
  generate adapter or llama.cpp; those are operator env
  (`BTX_MODEL_GENERATE` / `BTX_LLAMA_CLI`).
- Not a network inference server.
- Not a reason to stop a live production `btxd`.
- Not a claim that GitHub issue #138 is closed.
