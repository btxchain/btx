# BTX 0.34.8 — pre-merge development (first-run, JIT capability, HCP, Cognitive Reserve)

**Status:** **pre-merge development**. `CLIENT_VERSION` is **0.34.8** with
`CLIENT_VERSION_IS_RELEASE=false`. This is not a shipping tag and not a
consensus change. **0.34.7** remains the last released client.

This note is the public explanation of the whole 0.34.8-dev surface that
lands on top of merged 0.34.7: first-run conveniences, NETWORK-02 packages,
Just-in-Time modular capability (`btx-capabilityd`), Hosted Control Plane
HCP/1 (`btx-hcpd` / `btx-hosted`), Cognitive Reserve v1.1 (CR11 negotiated
extension of HCP), Cognitive Reserve Layer v1.2 (CRL/1.2, 43 additive ops
on the same engine), isolated-regtest proofs, and the precompiled archive
matrix. It is written so a reviewer who has not followed the private tree
can still see **what shipped in source**, **what was packaged**, and **what
is honestly NOT_RUN**.

People: [HUMANS.md](../../HUMANS.md),
[doc/modelnet/first-run.md](../modelnet/first-run.md),
[doc/hosted/README.md](../hosted/README.md).
Agents: [AGENTS.md](../../AGENTS.md),
[doc/modelnet/agent-recipes.md](../modelnet/agent-recipes.md).
RPC: [doc/modelnet/rpc.md](../modelnet/rpc.md).
HCP: [doc/modelnet/hcp/](../modelnet/hcp/).
CR v1.1: [doc/modelnet/crf/](../modelnet/crf/).
CRL/1.2: [doc/modelnet/crl12/](../modelnet/crl12/).

## What this release is (and is not)

0.34.7 made the Native Model Network work as a **two-plane** product
(`btxd` money + `btx-modeld` models). 0.34.8-dev adds the missing **operator
and agent happy path**, then three more **non-monetary** control surfaces
that never share a process with consensus:

| Plane | Process | Owns in 0.34.8-dev |
|---|---|---|
| Monetary | `btxd` | ExactReplay, wallet, issuance, fork choice, BanMan, AddrMan. Additive JSON only (`getsetupstatus`, `getmininginfo.first_run`, HCP/model RPC **proxy**). |
| Model | `btx-modeld` | first-run identity, import/host/share, swarm pieces, search cards, bounty drafts, NETWORK-02 packages, cloud/watch/mirror RPCs |
| Capability (JIT) | `btx-capabilityd` / `btx-capability` | resolve → acquire missing verified assets → local residency lease. Not remote inference. `ensurebtxcapability` is **IMPLEMENTED_LAB**: it runs the local fixture path for a granted plan and does not yet dereference recipe digests (`canonical_bytes_verified:false`, `acquired_bytes` is the fixture length, not the plan's requested bytes). |
| Hosted (HCP/1) | `btx-hcpd` / `btx-hosted` | typed catalogue, envelope (`object_type`, `body`, `body_id`, `signer_key_id`, `signature`), walletless discovery. CR11 and CRL/1.2 are **negotiated extensions of this plane**, not a fifth daemon. |

Hard product invariants (unchanged from 0.34.7, restated because this PR is
large):

- **No consensus / ASERT / header-PoW / issuance / ExactReplay change.**
- **`automatic_spend_atoms` stays 0.** A package, capability, or HCP job
  does not authorize its own spend.
- **No remote inference marketplace.** Local use is the end of acquisition.
- **No `-modelindex`.** Catalog is not PieceStore/S3.
- **URI `dn=` stays on `copy_text`.** Canonical `btx://` has no query string.
- **Public HTTP capability methods stay 405** on `btxd` / `btx-modeld`.
- **OAuth never in `btxd`.**
- **Import never becomes a custody credit.** Portfolio instructions are
  draft-only. Never invent AUM/AUC.
- **uTP/QUIC remain NONSHIPPING.**
- **Core package codec stays v1** in this tree (R7 vectors). Core v4 is
  not this PR.
- **Jobs that the engine cannot honestly keep in-flight** (cancel of a
  still-running remote worker, live HSM, live CEX) stay **HONEST_NOT_RUN**,
  never a faked PASS.

A node with **no** pin membership, **no** attestor key, and **no**
trusted-mirror pin must still reach tip from ExactReplay alone. Operator
fleet observation is **not** a 0.34.8 release bar.

## Precompiled archives (pre-merge)

Archives are **0.34.8-dev** (`IS_RELEASE=false`). They are review/test
assets, not a GitHub Releases cut. Packaged `bin/btxd` is a `#!/bin/sh`
wrapper; `ldd bin/btxd` is not verification. Gate:
`python3 scripts/release/verify_release_btxd.py` on the **real**
`libexec/btxd.real` (ZMQ + `btxd -version`).

Every flavor is configured `-DWITH_ZMQ=ON -DWITH_MODELNET=ON` and, when
present, ships the sibling helpers `btx-modeld`, `btx-modelcheck`,
`btx-open`, `btx-hcpd`, `btx-hosted`, `btx-capability`, `btx-capabilityd`.

| Platform id | Archive | How it was produced | Honest status |
|---|---|---|---|
| `linux-x86_64` | `btx-0.34.8-dev-x86_64-linux-gnu.tar.gz` | GCC 13 Release, CPU MatMul | Packaged and `verify_release_btxd` PASS |
| `linux-x86_64-cuda13` | `btx-0.34.8-dev-x86_64-linux-gnu-cuda13.tar.gz` | CUDA toolkit 13, `BTX_CUDA_ARCHITECTURES=120`, static cudart + bundled `libcublasLt` `$ORIGIN` | Compile+package when the CUDA tree links; **GPU golden / nvidia-smi runtime is NOT_RUN** (driver/NVML mismatch on the compile host; this archive is not a production-signer replace) |
| `linux-x86_64-cuda12` | — | No CUDA 12 toolkit on the build hosts | **HONEST skip** |
| `macos-arm64` / `macos-arm64-metal` | `btx-0.34.8-dev-arm64-apple-darwin.zip` (or `.tar.gz`) | Apple clang, `-DBTX_ENABLE_METAL=ON`, precompiled `*.metallib` | Compile+package on Apple silicon; Metal **hardware** goldens remain NOT_RUN unless a later lab row says PASS |
| `linux-arm64` | — | No aarch64 Linux host in this pre-merge | **HONEST skip** |
| ROCm / `BTX_ENABLE_HIP` | — | `hipcc` exists on one Linux host, but `rocminfo` fails (`HSA_STATUS_ERROR`, deprecated doorbell — NVIDIA device, not a usable AMD agent). No gfx* image was compiled. | **HONEST skip** |

Do not install these archives over a live production `libexec/btxd.real`.
Isolated-regtest uses a **second path** and a throwaway datadir.

## Planes and specs implemented in this pre-merge

### 1. First-run / doctor / share cards

See rounds 1–3 below. `btx-modeld` mints a research publisher identity on
first start. `importmodel` / `hostmodel` pin, demand-seed, and publish a
signed search card. `contrib/modelnet/btx-model` is the person/agent CLI
(never spend, never inference).

### 2. NETWORK-02 packages, cloud, watches, swarm

`.btxbundle`, ImportPlan, erasure, SUBPIECE_V1, origin-offer, evaluated
transport, FakeS3 unit tests, MinIO docker lab, LAN stampede, multipiece
swarm recovery. Live Hugging Face WAN, live R2 WAN, 400 GiB body, torrentd
as a process: **NOT_RUN**.

### 3. Just-in-Time Modular Capability (BTX-SPEC-0348-CAPABILITY-01)

`btx-capabilityd` is the local capability service: an agent asks for a
capability; BTX resolves an exact implementation, acquires **only the
missing verified assets**, places them in a local memory tier, and returns
a generation-bound readiness lease. This is **local intelligence
preparation**, not a download-and-forget helper and not a prompt router.

**Honesty note (#168).** The acquire step is **IMPLEMENTED_LAB**, not a
live digest fetch: `ensurebtxcapability` currently runs the local CPU
fixture path for a granted plan. It does not yet dereference the plan's
recipe digests, so its result reports
`implementation_status: "IMPLEMENTED_LAB"`, `canonical_bytes_verified:false`,
and `acquired_bytes` = bytes of the fixture actually written — never the
plan's requested byte contract. `percent_ready` therefore cannot reach 100
on the fixture path, and `ready` stays false. Do not read a granted plan +
fixture lease as a completed acquire.

Breaking **model-plane** schemas is allowed with versioning. Breaking
**monetary consensus** is not. Hardware backends without the device are
NOT_RUN, not deleted.

### 4. Hosted Control Plane HCP/1

Fourth plane. Envelope authentication:
`SHA384(UTF8("BTX/HCP/"+object_type+"/v1") || 0x00 || LE64(len) || BTX-PJSON1(body))`
with ML-DSA-44 (unchanged). `DispatchHcpRpc` routes helper methods.
Walletless lab is off unless `-cr12=1`. Public HTTP on money/model daemons
stays 405. Dual Job/envelope path via `return_job=true`. 16 MiB binary
stage vs 1 MiB JSON `max_body_bytes`.

### 5. Cognitive Reserve v1.1 (CR11)

Negotiated HCP/1 extension. Same `HcpEngine`, same ledger, same
downloader. No brand dispatch. Draft-only portfolio instructions.

### 6. Cognitive Reserve Layer v1.2 (CRL/1.2)

Additive on the **same** engine: preserve the prior 84 ops and old signed
types; add **43** ops and **18** V1_2 types. Nine CRL12 roles. Spec GET
positions require `as_of` + `observed_cutoff`. Package `TYPE_CONTRACTS`
names are accepted inbound; outbound signed strings stay engine names.
`RecordBlocked` uses `BINDING_REVOKED` when bindings exist and none are
ACTIVE. Jobs are created SUCCEEDED immediately in this tree; in-flight
cancel is HONEST_NOT_RUN. Combined contract is 127 ops. No Core v4, no
second engine.

## What was proven vs what is honest NOT_RUN

Proven in **isolated-regtest** (second process/path, throwaway datadir,
never the production signer): first-run CLI + functional, hosting
default/lifecycle, bridge-matrix, quic-absent, swarm-multipiece,
unique-todos, CR12 journeys J01–J20 + scale, HCP remaining, packages,
MinIO docker, LAN stampede, R10 MiniWallet path, native CR12 suites.

**HONEST_NOT_RUN / WITH_GAP / NONSHIPPING** (do not treat as PASS):

- Wallet `sign` F2; `-modelindex`; `BUILD_GUI` on the Linux compile host
- Live R2 / Hugging Face WAN; 400 GiB I/O; 10M anti-entropy; 1000
  downloaders; 20-buyer; mixed-0.34.7 fleet interop
- uTP/QUIC (NONSHIPPING); `torrentd` as a process
- CUDA/Metal **hardware** goldens (distinct from compiling those archives)
- Catalog-on-S3; Core v4; `WITH_MODELNET=OFF` second tree
- Live CEX / HSM; env-gated process rows that need extra lab boxes
- In-flight job cancel; Journeys HTTP J02 without a helper (process LAN
  row is the proof instead)
- `e2e-swarm-live.sh` 45-byte fixture (WITH_GAP); sibling multipiece is
  the multi-piece proof
- linux-arm64 archive; CUDA 12 archive; ROCm/HIP archive
- Production signer upgrade (explicitly out of this PR)

## Reviewer map

| Path | Why it is in this PR |
|---|---|
| `src/modelnet/helper.cpp`, `src/rpc/modelnet.cpp` | first-run + proxy JSON, `addmodelnode` object `{ok, added, automatic_spend_atoms:0}` |
| `src/modelnet/hcp_*.cpp`, `src/hcpd.cpp` | HCP/CR11/CRL/1.2 engine (`-cr12=0\|1`) |
| `src/capabilityd.cpp` | JIT capability daemon |
| `contrib/modelnet/` | `btx-model`, e2e scripts, recipes, CRL/1.2 packaged specs |
| `test/functional/feature_modelnet_*.py` | first-run, JIT, HCP, CR11, CR12, packages, security R10, LAN stampede |
| `scripts/release/package_release_archive.py` | optional siblings now include HCP + capability binaries |
| `doc/modelnet/crl12/`, `doc/modelnet/hcp/`, `doc/modelnet/crf/` | specs copied in-tree for implementers |

Do not commit operator hostnames, `.0348-*.local` extract trees, live
datadirs, or precompiled tarballs into git. Tarballs live next to the
review workspace, not in the public tree.

People: [doc/modelnet/first-run.md](../modelnet/first-run.md). Agents:
[doc/modelnet/agent-recipes.md](../modelnet/agent-recipes.md) and
[AGENTS.md](../../AGENTS.md). RPC: [doc/modelnet/rpc.md](../modelnet/rpc.md).

0.34.7 made the model plane work. 0.34.8 makes the happy path **automatic**:

- `btx-modeld` creates a local ML-DSA **research publisher** identity on first
  start (`identities.json` + secret under `tls/`). Not a wallet key.
- `importmodel` pins, demand-seeds, **and publishes a signed search card** by
  default (format/family/quantization inferred from filenames). Pass
  `{"publish":false}` to skip. Result includes `share` (`uri`, `copy_text`,
  family/format/quantization, `signed`) and `next_actions`.
- `publishmodelsearchrecord` **always signs**. It creates the identity if the
  helper has none. Unix RPC waits up to 24h for large imports (`importmodel` /
  `hostmodel` / `getmodel` / `waitformodelevent` / `scanmodelwatch`); other
  helper methods use a 120s reply timeout (the 30s PQ1 idle window no longer
  aborts `importmodel`).
- Catalog ingest **does not wipe** authored or signed search metadata. Directory
  cards keep family/format/tags after `searchmodels`. Search cards include
  `share.copy_text`.
- Models page Publish tab: import path, description, family, format, tags.

`automatic_spend_atoms` remains **0**. No operator hostnames in public trees.
The `btx://` URI still has no query string (`dn=` stays on `copy_text`).

### New and enriched RPCs (round 1)

Helper (`btx-modeld`, proxied by `btxd` when `-modelnet`):

| RPC | Role |
|---|---|
| `checkmodelsetup` | Doctor: `identity_ready`, `quota`, `pq1`, `ready_to_host`, `watch_dir`, `next_actions` |
| `hostmodel` | Alias of `importmodel` (pin + publish + demand-seed) |
| `previewmodelimport` | Size vs quota, `would_fit`, inferred labels; **no hash** |
| `getmodelsharecard` | `share` object for a local or search id |
| `getmodeltransfers` | Torrent-style list: uri, state, seeded, pinned, bytes, complete, served, received, ratio |
| `setmodelalias` | Add an alias, re-sign, bump `metadata_sequence` |
| `getmodelaliases` | `id` optional; omit it to list all local aliases |
| `scanmodelwatch` | Host new GGUF/SafeTensors from `-modelwatch=<dir>` (idempotent `watch-imported.json`) |
| `createbountydraft` | Title-only incomplete drafts allowed (`recipe_complete=false`, `missing_fields`) |
| `listbountydrafts` / `getbountydraft` | Local drafts; unpublished until the recipe is complete |

`getmodelnetworkinfo` now includes the same doctor fields (`identity_id`,
`ready_to_host`, `next_actions`). Every bounty mutation still returns
`next_actions` and `automatic_spend_atoms=0`. Incomplete drafts stay
unpublished; do not invent a council.

`btxd` (additive JSON only):

| RPC / field | Role |
|---|---|
| `getsetupstatus` | Chain/mining doctor + helper `checkmodelsetup` when connected |
| `getmininginfo.first_run` | `ready_to_mine`, `ibd`, `recommended_action`, `next_actions` (ExactReplay, not a hash lottery) |

CLI wrapper (never spend, never inference):
`contrib/modelnet/btx-model` verbs `doctor`, `host`, `preview`, `search`,
`get`, `share`, `transfers`, `alias`, `bounty-draft`, `watch-scan`. Copy-paste
JSON-RPC: `contrib/modelnet/recipes/`.

### Round 2 leftover verbs

BitTorrent / IPFS / Ollama / Public Pool / Gitcoin analogs that round 1 did
not cover. Ids parse `share.copy_text` (first `btx://` token) and **aliases**.

Helper:

| RPC | Role |
|---|---|
| `showmodel` | One card: `share`, local catalog, `aliases`, `bytes`, `next_actions` |
| `exportmodellink` | `.btx` JSON magnet analog (canonical `uri` + `copy_text`); optional write path |
| `openmodelshare` | Preview-only parse of copy_text / `.btx` file (same as `openbtxuri`) |
| `unhostmodel` | Unpin + unseed in one call (does not delete catalog bytes) |
| `removemodelalias` | Drop one name, re-sign |
| `getmodel` / `showmodel` | Resolve **alias** (`ollama pull NAME`) |
| `hostmodel` of a `.btx` / copy_text file | Not hashed as weights; returns share card + `getmodel` next action |
| `getmodeltransfers` / `listmodels` | `name`, `aliases`, `imported_at`; live job `percent`, `bytes_per_sec`, `eta_s`, `job_id` |
| `checkmodelsetup` | `remaining_bytes`, `one_liner` |
| `searchmodels` empty params | Default `scope: LOCAL`. Cards already have `share`; add `next_actions` (`getmodel FREE_ONLY`) |
| `scanmodelwatch` | Skip when `would_fit` is false |

`btxd` (additive JSON only):

| RPC / field | Role |
|---|---|
| `getmininginfo.first_run` | `blocks`, `peer_count`, `headers`, `verificationprogress` (`0..1`), `one_liner` |
| `getsetupstatus.one_liner` | Combined money+models sentence for agents |

CLI (`contrib/modelnet/btx-model`): `init`, `ls`, `show`, `pull` (getmodel by
alias), `unhost`, `link`, `rm-alias`. `bounty-draft @file.json` sends a JSON
terms object.

### Round 3 leftover verbs

JSON/CLI that round 2 did not document. Still **0.34.8-dev**, not a
shipping tag. `automatic_spend_atoms` stays **0**.

Helper:

| RPC | Role |
|---|---|
| `getmodelwatchstatus` | Side-effect-free: `watch_dir`, `configured`, `one_liner` |
| `scanmodelwatch` of a `.btx` / share file | **Opened** as a card (not imported as weights) |
| `updatebountydraft` | Patch a local draft in place (`missing_fields`, `checklist`, `one_liner`); never publishes |
| `deletebountydraft` | Drop a local draft (`deleted: true`, `one_liner`); never spends |
| `createbountydraft` / `getbountydraft` / `validatebountyterms` | `checklist`, `copy_text`, `terms_id_preview`, `one_liner` (first user-facing missing field) |
| `cancelmodeljob` | Stop a live retrieve; pieces stay (`btx-model pause`) |

`btxd` (additive JSON only):

| RPC / field | Role |
|---|---|
| `getmininginfo.first_run` | also `min_peers`, `connections_total`/`connections_out`, `network_active`, `uptime_s`, `version`, `tip_age_s`, `has_warnings` (sv2-ui tiles; display only) |
| `getsetupstatus.money.ready_to_mine` / `money.min_peers` | Same green-light as `first_run.ready_to_mine` |

CLI (`contrib/modelnet/btx-model`): `pause` (`cancelmodeljob`), `resume`
(`getmodel FREE_ONLY`), `ls --incomplete`, `bounty-draft --update` /
`--delete` / `--validate`. Copy-paste JSON-RPC: `contrib/modelnet/recipes/`
(`watch-status.json`, `bounty-update.json`, `bounty-delete.json`,
`pause.json`).

ExactReplay, fork choice, issuance, and `automatic_spend_atoms=0` are unchanged.

### Round 4 — 0.34.8-dev helper RPCs (`CLIENT_VERSION_IS_RELEASE=false`)

CLI wrapper verbs `cloud`, `follow`, `events`, `mirror`, `profile` plus
`--json` (agent door). Recipes: `cloud-status.json`, `follow-publisher.json`,
`events.json`, `infra-profile.json`. Docs:
[storage-backends.md](../modelnet/storage-backends.md),
[cloud-seeding.md](../modelnet/cloud-seeding.md),
[events.md](../modelnet/events.md),
[watches.md](../modelnet/watches.md),
[mirroring.md](../modelnet/mirroring.md).

**Honest status:** those helper RPCs **exist** in this 0.34.8-dev tree
(`CLIENT_VERSION_IS_RELEASE=false`). The CLI wrapper still **fails closed** if
an older helper is missing `getcloudstorageinfo` / `testcloudstorage` /
`setcloudstorage` / `watchmodelpublisher` / `getmodelevents` /
`waitformodelevent` / `getmodelprofile` / `setmodelmirror`. FakeS3 is
**unit-tested**. Live HTTPS/R2 is **NOT_RUN** (OpenSSL HTTPS transport is
compiled; live R2 WAN is not PASS). SCALE huge / 400GiB body stream is
**NOT_RUN** (headers-only unit test). `getmodelmirror` keep-N keeps
`automatic_spend_atoms` at **0**. Filesystem `scanmodelwatch` remains the
drop folder; it is not a publisher watch. GUI watches are 0.34.8-dev
**source** (`BUILD_GUI=OFF`; do not claim `bitcoin-qt` was built).
SubscriptionMandate `wallet_signed=false` is intentional, not a missing
spend to ship. Unknown helper RPC is `METHOD_NOT_FOUND` immediately (no
hang). Live helper-death log dump is **NOT_RUN** (no `btx-modeld` spawn).
No raw secrets in docs or argv (use `env:BTX_CLOUD_CREDENTIAL` /
`--secret-file`).

R2 AUTO is `SOURCE_FILES` + `STREAM_FILE`. Pieces stay the swarm unit; cloud
objects are optional backing. Qt Models page (source-only; `BUILD_GUI=OFF`
here) may show a labeled 0.34.8-dev profile / “cloud backing optional” panel
that never displays secrets.

ExactReplay, fork choice, issuance, and `automatic_spend_atoms=0` are unchanged.

### Round 5 — NETWORK-02 helper wiring (`CLIENT_VERSION_IS_RELEASE=false`)

ImportPlan, `.btxbundle`, per-stripe erasure, SUBPIECE_V1, object-layout
arithmetic, origin-offer, query summaries, and evaluated-transport RPCs exist
on `btx-modeld` and are proxied by `btxd`. `exportmodellink` remains the JSON
magnet analog; `createbtxpackage` is the binary bundle. HF/torrent integrity
is **not** publisher authorship. `createmodelrelease` wrap is capped at 64
MiB. GET `/files` never concatenates the object in RAM.

**Honest status:** libraries + helper RPC are unit-tested. Live Hugging Face
HTTP, `btx-torrentd` as a process, live R2 WAN, SCALE huge, GUI
(`BUILD_GUI=OFF`), wallet-signed SubscriptionMandate, uTP/QUIC, and 10M
catalog remain **NOT_RUN** / **NONSHIPPING**. R2 AUTO stays `SOURCE_FILES`.
`automatic_spend_atoms` stays **0**.
