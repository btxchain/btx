# BTX auto-update: release & bootstrap plan

This document is the operator-facing contract for the signed auto-update channel
implemented by `src/node/autoupdate.*` (the node side) and
[`install.sh`](./install.sh) (the builder/installer the node launches). It
exists to answer one question precisely: **how do we roll the first
post-quantum-signed release to a fleet without bricking nodes that predate the
post-quantum verifier?**

## Threat model recap

BTX is a post-quantum chain. The auto-update channel can ship code to every
node, so it is the single most powerful trust path in the system and **must
itself be quantum-safe**. A classical (secp256k1/ECDSA) signature on the release
manifest would be the weakest link: an adversary able to forge it could push
arbitrary code fleet-wide. Hence the default release-signature scheme is
**ML-DSA-44** (`DEFAULT_AUTOUPDATE_RELEASE_PUBKEY_ALGO` in `node/autoupdate.h`),
not secp256k1.

## How verification works

The node fetches `version.txt` (the manifest) and `version.txt.sig` (a detached
signature over the raw manifest bytes), verifies the signature against the
operator-configured release public key, then fetches + hash-checks the installer
script and execs it. The installer independently re-verifies the manifest (and
any signed `git_commit`) before building.

- **PQ schemes (`ml-dsa-44`, `slh-dsa-128s`):** verified with
  `btx-util verifyupdatesig <algo> <pubkey-hex> <file> <sig-file>`. This means
  **the installer needs a `btx-util` binary present** to verify a PQ-signed
  release.
- **Classical (`secp256k1`):** verified with `openssl dgst -verify`. No
  `btx-util` required.

The node hands the installer the scheme + key it used via
`BTX_AUTOUPDATE_PUBKEY_ALGO` / `BTX_AUTOUPDATE_PUBKEY`, and the directory of the
running node binary via `BTX_AUTOUPDATE_BIN_DIR`, so the installer can locate the
sibling `btx-util` portably (no `/proc` dependency on macOS/BSD).

## The bootstrap problem

A node that was installed **before** `btx-util` was shipped into the release tree
has no PQ verifier on disk. If such a node is configured for a PQ scheme, the
**first** PQ-signed update cannot be verified by the installer and is correctly
refused (fail-closed). We must not strand those nodes.

### Resolution (the release plan)

1. **v0.31 ships `btx-util` in every release tree and on `PATH`.**
   `install.sh` builds with `-DBUILD_UTIL=ON`, copies `btx-util` into
   `<release>/bin/`, and `activate_release_tree` symlinks it into the link dir
   alongside `btxd`/`btx-cli`/`btx-wallet`. After any v0.31+ update, a PQ
   verifier is guaranteed present for the *next* cycle. `resolve_btx_util_path`
   finds it via, in order: `BTX_UTIL`, `BTX_AUTOUPDATE_BIN_DIR`,
   `current/bin/btx-util` / link dir, the running btxd's sibling (Linux
   `/proc`), then `PATH`.

2. **Legacy first hop is classical only for nodes that predate `btx-util`.**
   If an old install has no local `btx-util`, operators can run one update with
   `-autoupdatepubkeyalgo=secp256k1` and the historical classical release key
   (documented in `node/autoupdate.h`). That hop only needs `openssl`, which is
   already a hard dependency. It delivers a modern release — and therefore
   `btx-util` — to the node.

3. **Switch to PQ for every subsequent hop.** Once v0.31+ is active (so
   `btx-util` exists), reconfigure the node to the PQ scheme
   (`-autoupdatepubkeyalgo=ml-dsa-44 -autoupdatepubkey=<2624-hex>`). From here
   the powerful update path is fully quantum-safe.

New installs and current release archives skip step 2 entirely: they already
have `btx-util`, so they can be PQ-only from the first hop.

### Why the default is active on mainnet

`DEFAULT_AUTOUPDATE_RELEASE_PUBKEY` is a compiled-in ML-DSA-44 release public
key, and mainnet auto-update defaults to that PQ scheme. A btx.dev/DNS/TLS
compromise is not enough to ship code: the manifest, optional pinned commit, and
prebuilt artifacts still need signatures from the offline release key. Operators
can opt out or override the trust root with `-autoupdate=0`,
`-autoupdatepubkey=0`, or an explicit `-autoupdatepubkey` /
`-autoupdatepubkeyalgo` pair.

## Manifest fields

`version.txt` is JSON. Recognized fields:

| field | meaning |
| --- | --- |
| `version` | release version (compared against the running `CLIENT_VERSION`) |
| `repo_url` | source git remote to build from |
| `script_url` | installer script URL (must be under `BTX_TRUSTED_ORIGIN`) |
| `sig_url` | detached manifest-signature URL (defaults to `<manifest>.sig`) |
| `release_tag` / `git_ref` | preferred source ref to resolve |
| `git_commit` | optional: pin; installer refuses a mismatching resolved commit |
| `git_commit_sig_url` | optional: detached signature over `git_commit` (same scheme) |
| `rollout_percent` | optional staged-rollout percentage (0–100, default 100) — see below |
| `prebuilt` | optional map of `<platform-key> → {url, sig_url, sha256?}` prebuilt binaries — see below |

## Prebuilt signed binaries (with source-build fallback)

Building from source on every node is slow and needs a toolchain. The manifest
may instead offer prebuilt binaries per platform; the installer downloads,
verifies, and installs the matching one, and **falls back to a source build**
when none matches or verification fails.

```jsonc
"git_commit": "<full 40-hex commit the binaries were built from>",
"prebuilt": {
  "linux-x86_64-cuda13": {
    "url":    "https://btx.dev/bin/btx-0.33.0-x86_64-linux-gnu-cuda13.tar.gz",
    "sig_url":"https://btx.dev/bin/btx-0.33.0-x86_64-linux-gnu-cuda13.tar.gz.sig",
    "sha256": "<hex>"
  },
  "linux-x86_64-cuda12": {
    "url":    "https://btx.dev/bin/btx-0.33.0-x86_64-linux-gnu-cuda12.tar.gz",
    "sig_url":"https://btx.dev/bin/btx-0.33.0-x86_64-linux-gnu-cuda12.tar.gz.sig",
    "sha256": "<hex>"
  },
  "linux-x86_64-glibc": {
    "url":    "https://btx.dev/bin/btx-0.33.0-x86_64-linux-gnu.tar.gz",
    "sig_url":"https://btx.dev/bin/btx-0.33.0-x86_64-linux-gnu.tar.gz.sig",
    "sha256": "<hex>"                       // optional, defense-in-depth
  },
  "linux-aarch64-glibc": { "url": "…", "sig_url": "…" },
  "linux-x86_64-musl":   { "url": "…", "sig_url": "…" },
  "darwin-arm64":        { "url": "…", "sig_url": "…" }
}
```

- **Platform key** is `<os>-<arch>[-<flavor-or-libc>]`. On x86-64 glibc Linux,
  the installer uses a successful `nvidia-smi` probe to try the canonical
  `linux-x86_64-cuda13` / `linux-x86_64-cuda12` release keys before
  `linux-x86_64-glibc`. A CUDA 13-capable driver tries CUDA 13, then the
  compatible CUDA 12 build, then CPU; a CUDA 12-capable driver tries CUDA 12,
  then CPU. A toolkit or `nvcc` alone does not select a GPU build. Other Linux
  platforms distinguish `glibc` vs `musl` (so an Alpine node never installs a
  glibc build), and both `aarch64` and `arm64` spellings are tried.
- **Trust** is anchored exactly like the manifest: the tarball's detached
  signature is verified under the SAME scheme/key (`btx-util verifyupdatesig` for
  PQ, `openssl` for classical). The artifact URLs must also be under
  `BTX_TRUSTED_ORIGIN`. Because the install only runs when `git_commit` is pinned
  in the signed manifest, the prebuilt is bound to a specific signed commit.
- **Fallback:** a missing/mismatched/unverifiable artifact (or a platform with no
  entry) logs a warning and the installer builds from source — availability is
  preserved without weakening trust. `BTX_PREFER_PREBUILT=0` forces source builds.
- The prebuilt tarball must contain `bin/btxd`, `bin/btx-cli`, and
  `bin/btx-util`; `bin/btx-wallet` is recommended when built. Shipping
  `btx-util` keeps the next cycle's PQ verifier present. Layout `bin/…`,
  `<name>/bin/…`, or binaries at the root all work.

### CI signing pipeline (release engineering)

Per release, for each supported `(os, arch, libc)`:

1. Build `btxd`/`btx-cli`/`btx-wallet`/`btx-util` from the **pinned commit**
   (reproducible flags; matching libc — e.g. build musl artifacts in an Alpine
   container).
2. `tar -czf btx-<ver>-<platform>.tar.gz bin/` and record `sha256`.
3. Sign the tarball bytes with the **offline release key** in the release scheme
   (ML-DSA-44 by default): produce `…​.tar.gz.sig`. Verify locally with
   `btx-util verifyupdatesig <algo> <pubkey-hex> <tarball> <sig>` → `OK`.
4. Sign `version.txt` (and optionally `git_commit`) the same way.
5. Publish `version.txt`, `version.txt.sig`, `install.sh`, and every
   `…​.tar.gz` + `…​.tar.gz.sig` under `https://btx.dev/`.

The private key never touches CI runners that fetch untrusted input; signing runs
on an isolated/offline host (`../btx-release-key/`).

## Request metrics

Auto-update requests append transport-only query parameters so release operators
can see which client versions, platforms, architectures, and rollout cohorts are
polling/installing without changing signed manifest bytes. The default request
metrics are intentionally aggregate-only: no wallet data, addresses, peer IPs,
transaction IDs, hardware serials, or persistent client identifier are added.

| parameter | meaning |
| --- | --- |
| `btx_au=1` | identifies the request as part of the auto-update flow |
| `btx_version` | running client version, e.g. `0.33.0` |
| `btx_platform` | operating system family, e.g. `linux` or `darwin` |
| `btx_arch` | client architecture, e.g. `x86_64` or `aarch64` |
| `btx_cohort` | staged-rollout bucket in `[0,99]` |

Operators may disable this request tagging with `-autoupdatetelemetry=0`.
Operators running a controlled canary fleet may opt in to a persistent random
UUID with `-autoupdatetelemetryclientid=1`; that sends `btx_client_id` and stores
the UUID at `<datadir>/autoupdate/client-id`. Leave it off for normal public
nodes.

Startup checks run after `-autoupdateinitialdelay` plus at most
`-autoupdateinitialjitter` seconds, so urgent releases are normally discovered
within a short window after restart. Transient manifest/signature/script fetch
failures retry from `-autoupdateretryinterval` with exponential backoff instead
of waiting the full steady-state `-autoupdateinterval`.

## Staged / canary rollout

`rollout_percent` (aliases `rollout`, `canary_percent`) in the **signed** manifest
bounds how much of the fleet may apply a release. Each node computes a stable
cohort in `[0, 100)` — derived by default from a hash of its datadir, so it is
fixed across restarts but spread across the fleet — and applies the update only
when `cohort < rollout_percent`. A node outside the band reports
`rollout-deferred` (not an error) and re-checks on the normal interval, so simply
raising `rollout_percent` in the manifest widens the rollout with no node-side
change.

Because the percentage lives in the signed body it cannot be tampered with to
widen a rollout. Operators publish e.g. `rollout_percent: 5`, watch the canary
cohort's health/status logs, then ramp `25 → 50 → 100`. Combined with the
installer's health-probe rollback, a bad release is caught on a small fraction
of nodes first and each of those self-reverts.

Pin a node into a specific band with `-autoupdatecohort=<0-99>` (e.g. `0` for a
permanent early canary, a high value to update last).

## Signing a release (operator runbook)

```sh
# 1. Build version.txt with the fields above, pinning git_commit.
# 2. Sign the raw manifest bytes with the release private key:
#    - PQ:        produce ML-DSA-44 signature over version.txt  -> version.txt.sig
#    - classical: openssl dgst -sha256 -sign release.pem -out version.txt.sig version.txt
# 3. (optional) sign the pinned commit id the same way -> git_commit.txt.sig
# 4. Publish version.txt, version.txt.sig, install.sh under https://btx.dev/.
# Verify locally before publishing:
btx-util verifyupdatesig ml-dsa-44 <pubkey-hex> version.txt version.txt.sig   # -> OK
```

## Operator knobs (installer env)

Key environment variables (see the top of `install.sh` for the full list):

- `BTX_AUTOUPDATE_PUBKEY_ALGO` / `BTX_AUTOUPDATE_PUBKEY` — release scheme + key
  (normally forwarded by the node).
- `BTX_HEALTH_PROBE` (default 1) / `BTX_HEALTH_TIMEOUT_SECONDS` (default 60) —
  post-restart RPC health probe; on failure the installer rolls back to the
  previously active release.
- `BTX_RELEASE_RETENTION` (default 3) — release trees and build worktrees kept.
- `BTX_MIN_FREE_GB` (default 6) — refuse to start a build below this free space.
- `BTX_PREFER_PREBUILT` (default 1) — use a signed prebuilt matching this
  platform when the manifest offers one; set 0 to always build from source.
- `BTX_USE_CCACHE` (default 1), `BTX_CACHE_ROOT` — build cache controls.
- `BTX_STATUS_FILE` (default `<install-root>/status.jsonl`) — append-only JSON
  progress log (stages: preflight, verify-manifest, fetch-source, build,
  verify-binaries, activate, restart, health-probe, rollback, complete; plus a
  `failed` record pinning where a run stopped). Set empty to disable.
- `XDG_{DATA,BIN,CACHE}_HOME` — honored for default paths; required (or explicit
  `BTX_INSTALL_ROOT`/`BTX_LINK_DIR`/`BTX_CACHE_ROOT`) for service accounts with
  no usable `$HOME`.
