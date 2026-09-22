# BTX 0.34.9-dev — Registry Independence (tester snapshot)

**Status:** development snapshot for
[PR 198](https://github.com/btxchain/btx/pull/198).
`CLIENT_VERSION` is **0.34.9** with `CLIENT_VERSION_IS_RELEASE=false`.
This is **not** a shipping tag and **not** a consensus change.

Use it to exercise origin-independent fetch, piece routing, ModelPack import,
and the `btx-model` agent door. Do not treat it as `v0.34.8` or as
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

Protocol: [registry-independence.md](../modelnet/registry-independence.md).
Agent recipes §10: [agent-recipes.md](../modelnet/agent-recipes.md).

## What this is not

- Not `--latest`. Leave current shipping / rc tags alone.
- Not a recut of `v0.34.8`.
- Not signed Guix. Treat binaries as a convenience for testers of PR 198.
- Not CUDA. Not macOS. Not Windows.
- Not a reason to stop a live production `btxd`.
