# First run — host, seed, search, share

This is the **people** walkthrough. You do not need a wallet, coins, mining,
or a chain sync to host a local model and share its `btx://` URI. Inference
stays **local after acquire**. Nothing here spends BTX.

Agents: stop and read [agent-recipes.md](agent-recipes.md) and
[AGENTS.md](../../AGENTS.md). Tests and every scenario:
[howto.md](howto.md). Zero-wallet CLI: [researcher-quickstart.md](researcher-quickstart.md).

Truncated URIs (`btx://…`) in examples are **placeholders**. A complete
synthetic MODEL token (not a hosted model):

```text
btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25
```

Last shipping tag is **0.34.7**. This tree is **0.34.8-dev**
(`CLIENT_VERSION_IS_RELEASE=false`). 0.34.8 is not a shipping tag.

## What you are about to do

| Step | Human meaning | Analog |
|---|---|---|
| Doctor | Can this machine host? Sync progress if you also mine | Public Pool / sv2-ui first-run wizard |
| Host | Pin a local GGUF or SafeTensors and announce it | `ipfs add` / `ollama create` |
| Seed | Keep serving it to peers inside quota | torrent seeding (on by default) |
| Transfers | Live list with rate / percent / ETA | Transmission torrent list |
| Files / path | Per-file size, hash, and where the local copy lives | torrent Files tab / `hf --local-dir` |
| Search | Find models by what they do, filter by format / size / providers | LM Studio catalog filters, without a central hub |
| Show / pull | One card, then fetch by name | `ollama show` / `ollama pull NAME` |
| Share / link | Copy a `btx://` card or write a `.btx` file | magnet link / `.torrent` file |
| Open share | Preview a pasted card or `.btx` file | `ipfs cat` by CID |
| Unhost | Stop seeding and unpin in one step | `ollama rm` / stop seed |
| Watch folder | Drop new files in a directory; they host themselves | qBittorrent watch folder |

Pickle / `.pt` / `.py` / `.so` are refused. A structure check is not a claim
that the model is useful or safe. Automatic spend stays **0**.

Ids in every verb below accept a canonical `btx://`, a hex digest, an
**alias**, `share.copy_text` (the first `btx://` token), or a `.btx` link
file. The URI itself has **no query string**; display names stay on
`copy_text`, not in `btx://`.

## 0. Doctor

Ask once before you import. With packaged `btxd` (helper supervised):

```bash
btx-cli getsetupstatus
btx-cli checkmodelsetup
btx-cli getmininginfo
```

Standalone helper (no chain):

```bash
contrib/modelnet/btx-model init
contrib/modelnet/btx-model doctor
```

Unix RPC (one JSON line on the helper socket):

```json
{"jsonrpc":"1.0","id":1,"method":"checkmodelsetup","params":[]}
```

`checkmodelsetup` is the model-plane doctor:

| Field | Meaning |
|---|---|
| `identity_ready` | Local ML-DSA research publisher exists (`identities.json`). Created automatically on first helper start. **Not a wallet key.** |
| `quota` | Payload budget (`-modelstorage=auto` packaged default; `0` stores nothing) |
| `remaining_bytes` | Quota minus used payload (`0` when quota is `0`) |
| `pq1` | Strict PQ1 (OpenSSL 3.5+ ML-KEM-768 / ML-DSA-44) or fail-closed |
| `ready_to_host` | Identity + quota + PQ1 are enough to import and seed |
| `watch_dir` | `-modelwatch=` path, or empty if unset |
| `one_liner` | Single sentence for a status bar or agent (`Ready to host.` / follow `next_actions`) |
| `next_actions` | What to do next (allocate storage, install OpenSSL 3.5, host a file, …) |

`getmodelnetworkinfo` repeats the same doctor fields (`identity_id`,
`ready_to_host`, `next_actions`) plus the usual helper snapshot.

`getsetupstatus` (on `btxd`) **combines** chain/mining first-run with the
helper doctor when the helper is connected. Read **`one_liner`** first: it
is the combined money+models sentence. `money` includes `blocks`,
`peer_count`, `headers`, `verificationprogress`, `ready_to_mine`, and
`min_peers` when the mining chain guard is in scope. Mining first-run lives
on `getmininginfo.first_run`:

| Field | Meaning |
|---|---|
| `ready_to_mine` | Tip is not IBD and the chain guard is healthy |
| `ibd` / `initialblockdownload` | Still catching up (Core latch; may be age-only) |
| `ibd_kind` | `none` / `loading` / `insufficient_chain_work` / `age_only` |
| `template_issuable` | GBT would not refuse for historical catch-up |
| `blocks` | Local tip height |
| `peer_count` | Outbound peers the mining chain guard counts |
| `min_peers` | Configured minimum for a healthy guard decision |
| `headers` | Best header height (same idea as `getblockchaininfo.headers`) |
| `verificationprogress` | Estimate toward network tip, `0..1` (same idea as `getblockchaininfo`) |
| `connections_total` / `connections_out` | Live P2P counts (`null` if connman is unavailable) |
| `network_active` | Whether P2P is enabled |
| `uptime_s` / `version` | Process uptime and `btxd` version (sv2-ui footer analog) |
| `tip_age_s` | Seconds since the local tip's block time |
| `one_liner` | Single sentence (`IBD 0.42; wait for tip` / `Ready to mine ExactReplay.`) |
| `recommended_action` | Chain-guard string |
| `next_actions` | Including `getsetupstatus` |

`getsetupstatus.money` also carries `ibd_kind`, `template_issuable`, and
`connections.{in,out,total}` so a wizard does not have to join three RPCs.

If `ready_to_host` is false, follow `next_actions`. Typical fixes: give the
helper a positive `-modelstorage` (or keep packaged `auto`), and use OpenSSL
3.5+ so PQ1 is ready.

## 1. Host a local model

Qualify (no execution), then host. `hostmodel` is the happy-path alias of
`importmodel`: **pin + signed search card + demand-seed** by default.

```bash
btx-modelcheck /path/to/model.safetensors
btx-cli hostmodel /path/to/dir
# same default:
btx-cli importmodel /path/to/dir
contrib/modelnet/btx-model host /path/to/dir
contrib/modelnet/btx-model preview /path/to/dir   # size vs quota; no hash
```

```json
{"jsonrpc":"1.0","id":1,"method":"previewmodelimport","params":["/path/to/dir"]}
{"jsonrpc":"1.0","id":1,"method":"hostmodel","params":["/path/to/dir"]}
{"jsonrpc":"1.0","id":1,"method":"importmodel","params":["/path/to/dir"]}
```

First helper start writes `identities.json` and an ML-DSA secret under `tls/`.
You do not call `createmodelidentity` first.

Pass `{"publish":false}` only when you want a local pin **without** a signed
search card. Pin stays on unless you pass `{"pin":false}`. Unix RPC waits up
to **24h** for `importmodel` / `hostmodel` / `getmodel` / `waitformodelevent` /
`scanmodelwatch` so a large import is not killed by the 30s PQ1 idle window.
Ordinary helper methods use a **120s** unix reply timeout.

The result always includes a **share card** and `next_actions`:

```json
{
  "uri": "btx://…",
  "seeded": true,
  "search_published": true,
  "share": {
    "uri": "btx://…",
    "copy_text": "btx://…",
    "family": "qwen3",
    "format": "safetensors",
    "quantization": "IQ4_XS",
    "signed": true
  },
  "next_actions": ["copy share.copy_text", "searchmodels", "getmodeltransfers"]
}
```

Family / format / quantization are inferred from filenames when you did not
author them. Copy `share.copy_text` (it contains the canonical `btx://` URI).

`previewmodelimport` reports size versus quota, `would_fit`, and the same
inferred labels. It does **not** hash and does not write the catalog.

A `.btx` link file or a text file whose contents are `copy_text` is **not**
weights. `hostmodel` / `btx-model host` of that path returns the share card
and a `getmodel` next action; it does not hash the file as a model.

```bash
btx-cli hostmodel ./qwen3.btx
contrib/modelnet/btx-model host ./qwen3.btx
```

## 2. Seed (already on)

With `-modelseed=auto` (the default once quota is positive) a successful
`hostmodel` / `importmodel` / `getmodel` is **already seeded**. `seedmodel` is
only for `-modelseed=manual`. Preserve-rare (fetch under-replicated models
into spare space) stays off unless `-modelpreserverare`.

Torrent-style list:

```bash
btx-cli getmodeltransfers
contrib/modelnet/btx-model transfers
contrib/modelnet/btx-model ls
```

| Field | Meaning |
|---|---|
| `uri` | Canonical `btx://` |
| `name` | Display / canonical name |
| `aliases` | Local Ollama-style names |
| `imported_at` | Catalog import time |
| `state` | Local transfer state |
| `seeded` / `pinned` | Serving / keep |
| `bytes` / `complete` | Size and whether pieces are present |
| `served` / `received` / `ratio` | Useful bytes out / in, and the ratio |
| `percent` | 0–100 of payload when a retrieve job is live |
| `bytes_per_sec` | Live retrieve rate (omit or `0` when idle) |
| `eta_s` | Seconds remaining when a rate is known |
| `job_id` | Live retrieve job id |

`listmodels` carries the same `name` / `aliases` / `imported_at` columns and
the same live-job rate fields. To stop a live retrieve without deleting
pieces: `btx-model pause <job_id>` (`cancelmodeljob`). To fetch again:
`btx-model resume qwen3-local` (`getmodel FREE_ONLY`, same as `pull`).
Pinned models are never automatically evicted
(`pinmodel` / `unpinmodel`). To **unpin and unseed in one call**:

```bash
btx-cli unhostmodel 'qwen3-local'
contrib/modelnet/btx-model unhost qwen3-local
```

`unhostmodel` does not delete catalog bytes. It is stop-seed + drop Keep.

## 3. Search

The Models page default is a **network directory** (Latest), not a local-only
file manager. CLI with **empty params** lists **this node** (`scope: LOCAL`):

```bash
btx-cli searchmodels
btx-cli searchmodels '{"text":"coding agent","scope":"NETWORK"}'
contrib/modelnet/btx-model search "coding agent"
contrib/modelnet/btx-model ls
```

```json
{"jsonrpc":"1.0","id":1,"method":"searchmodels","params":[]}
{"jsonrpc":"1.0","id":1,"method":"searchmodels","params":[{"text":"coding agent","scope":"NETWORK"}]}
```

Coverage is always incomplete (`complete: false`): this node's current view,
not a global census. `scope: LOCAL` does not leave this node. Network queries
may be visible to consulted peers.

Each result card includes `share.copy_text` and `next_actions` (at least
`getmodel FREE_ONLY`) so you can paste or retrieve without another round
trip. Optional Ollama-style names:

```bash
btx-cli setmodelalias '<model_id>' 'qwen3-local'
btx-cli getmodelaliases
btx-cli getmodelaliases '<model_id>'
btx-cli removemodelalias '<model_id>' 'qwen3-local'
contrib/modelnet/btx-model alias '<model_id>' qwen3-local
contrib/modelnet/btx-model rm-alias qwen3-local
```

`setmodelalias` re-signs the search record and bumps `metadata_sequence`.
`getmodelaliases` with no id lists **all local** aliases.
`removemodelalias` drops one name and re-signs.

`getmodel` / `showmodel` / `btx-model pull` resolve that alias the same way
`ollama pull NAME` does:

```bash
btx-cli showmodel qwen3-local
btx-cli getmodel qwen3-local FREE_ONLY
contrib/modelnet/btx-model show qwen3-local
contrib/modelnet/btx-model pull qwen3-local
```

`showmodel` is one card: `share`, local catalog row, `aliases`, `bytes`,
`next_actions`. It does not retrieve and does not start a runtime.

## 4. Share

```bash
btx-cli getmodelsharecard '<model_id-or-btx://-or-alias>'
btx-cli exportmodellink '<model_id-or-alias>'
btx-cli exportmodellink '<model_id-or-alias>' ./qwen3.btx
btx-cli openmodelshare ./qwen3.btx
contrib/modelnet/btx-model share '<model_id-or-alias>'
contrib/modelnet/btx-model link qwen3-local ./qwen3.btx
contrib/modelnet/btx-model open ./qwen3.btx        # card preview, never a fetch
```

Same `share` object as import: `uri`, `copy_text`, `family`, `format`,
`quantization`, `signed`. Works for a local catalog id, an alias, a search
hit, or pasted `copy_text`.

`exportmodellink` writes or returns a `.btx` JSON magnet analog: canonical
`uri` plus `copy_text`. Pass a filesystem path to write the file; omit the
path to get the JSON only.

`openmodelshare` is preview-only (same contract as `openbtxuri`): it parses
`copy_text`, a `.btx` file, or a `btx://` token. It does not spend, does not
auto-download, and does not start inference.

Opening a `btx://` URI **shows** the resource. Retrieve free with `getmodel`
/ `btx-model get` / `btx-model pull` in `FREE_ONLY` (the default).

## 5. Watch folder

Drop new GGUF / SafeTensors into a directory. The helper hosts them the same
way as `hostmodel` (pin + signed card + seed). Already-imported names are
skipped (`watch-imported.json` under the model dir). A candidate that
`previewmodelimport` would report `would_fit: false` is **skipped** (not
imported, not hashed). A `.btx` / share file is **opened** as a card (not
imported as weights).

`getmodelwatchstatus` reports the configured path without scanning
(`watch_dir`, `configured`, `one_liner`).

```bash
btxd -modelwatch=/path/to/incoming
# standalone:
btx-modeld -modelstorage=auto -modelwatch=/path/to/incoming -modelhost
btx-cli getmodelwatchstatus
btx-cli scanmodelwatch
contrib/modelnet/btx-model watch-scan
```

```json
{"jsonrpc":"1.0","id":1,"method":"getmodelwatchstatus","params":[]}
{"jsonrpc":"1.0","id":1,"method":"scanmodelwatch","params":[]}
```

Empty `-modelwatch` is off. The doctor reports the configured path.

This **filesystem drop folder is not a publisher watch**. Publisher /
collection follow, event journal, and optional cloud backing exist in this
**0.34.8-dev** helper (`CLIENT_VERSION_IS_RELEASE=false`). FakeS3 is
unit-tested; live HTTPS/R2 is **NOT_RUN** (OpenSSL HTTPS transport is
compiled; live R2 WAN is not PASS). SCALE huge / 400GiB body stream is
**NOT_RUN**. The CLI wrapper still fails closed if an older helper has no
method. GUI watches are 0.34.8-dev source (`BUILD_GUI=OFF`; do not claim
`bitcoin-qt` was built). See [watches.md](watches.md), [events.md](events.md),
[storage-backends.md](storage-backends.md). No PASS.

## 6. Use it locally

Point a **local** runtime at `exportmodelpath`. BTX does not start that
runtime and does not expose it to the network. There is no inference seller
and no cloud **inference** fallback. Optional object-store backing (R2/S3)
is 0.34.8-dev: FakeS3 unit-tested, HTTPS transport compiled, live HTTPS/R2
**NOT_RUN**, and is not remote inference — see
[storage-backends.md](storage-backends.md).

Paid release/bounty flows are optional and still split prepare → sign →
submit. They are not part of first-run. Title-only bounty drafts
(`createbountydraft` / `btx-model bounty-draft`) stay local and unpublished
until the recipe is complete. Drafts return `one_liner` (first
user-facing `missing_fields` entry), a Gitcoin-style `checklist`, and
`copy_text: "draft_id=<hex>"`. Gitcoin-style file draft, save-in-place,
validate, and delete:

```bash
contrib/modelnet/btx-model bounty-draft @./terms.json
contrib/modelnet/btx-model bounty-draft --validate '<draft_id>'
contrib/modelnet/btx-model bounty-draft --update '<draft_id>' @./terms.json
contrib/modelnet/btx-model bounty-draft --delete '<draft_id>'
```

`automatic_spend_atoms` remains 0.

## `btx-model` cheat sheet

Never spends. Never inference. Scratch helper socket only.

| Verb | RPC |
|---|---|
| `init` / `doctor` | `checkmodelsetup` (`one_liner`). Prefer `getsetupstatus` on `btxd`. |
| `preview` / `host` | `previewmodelimport` / `hostmodel` (weights **or** `.btx` / copy_text) |
| `ls [--incomplete]` | `getmodeltransfers` (`--incomplete` keeps downloading / `percent<100`) |
| `show` | `showmodel` |
| `search` | `searchmodels` (CLI default `LOCAL`; catalog filters + `--fits` for this node's remaining storage) |
| `get` / `pull` | `getmodel` `FREE_ONLY` (`pull` is by alias/name) |
| `share` / `link` | `getmodelsharecard` / `exportmodellink` |
| `open` | `openmodelshare` (falls back to `openbtxuri`); preview only |
| `transfers` | `getmodeltransfers` |
| `pause` / `resume` | `cancelmodeljob` / `getmodel` `FREE_ONLY` (pieces stay on pause) |
| `files` | `getmodelmanifest` (per-file path/role/size/sha384; local model only) |
| `path` | `exportmodelpath` (verified local store root + source path; `hf --local-dir` analog) |
| `check` | `qualifymodel` (static structure check of a local path; no runtime) |
| `pins [--type pinned\|seeded\|both]` | `listmodels` filtered to kept/served rows (`ipfs pin ls` analog) |
| `alias` / `rm-alias` | `setmodelalias` / `getmodelaliases` / `removemodelalias` |
| `unhost` | `unhostmodel` |
| `bounty-draft` | `createbountydraft` (title string or `@file.json`); `--update` / `--delete` / `--validate` |
| `watch-scan` | `scanmodelwatch` (`getmodelwatchstatus` is RPC-only). Filesystem folder, not publisher follow. |

## 7. 0.34.8-dev optional (helper methods exist; not a shipping tag)

These verbs exist on `contrib/modelnet/btx-model` so agents have a
stable door. The helper in this tree implements the RPCs. If an older
helper does not implement the RPC, the wrapper **exits immediately**
(`method not found (0.34.8-dev; fails closed if helper lacks method)`).
Unknown `DispatchHelperRpc` is `METHOD_NOT_FOUND` immediately;
`automatic_spend_atoms` is not required on that error. That is not WAN
evidence and not a PASS. `automatic_spend_atoms` stays **0**. `--json` is
the agent door (stdout only). People keep stderr hints without `--json`.

| Verb | RPC (0.34.8-dev) |
|---|---|
| `cloud add` | `setcloudstorage` (endpoint/bucket/prefix/region/layout/provider/`credential_ref`; `--secret-file` or `env:NAME`, never a raw secret on argv) |
| `cloud test` / `cloud status` | `testcloudstorage` / `getcloudstorageinfo` |
| `follow publisher\|collection` | `watchmodelpublisher` / `watchmodelcollection` (`--action notify\|free-download\|prepare-funding`; default NOTIFY) |
| `events [--cursor N] [--wait S]` | `getmodelevents`; `waitformodelevent` only after a probe so unknown RPC cannot hang |
| `mirror --publisher / --keep-latest` | `getmodelmirror` / `setmodelmirror` |
| `profile show\|set` | `getmodelprofile` / `setmodelprofile` (`personal\|infrastructure\|mirror\|custom`) |
| `import-plan` | `executemodelimport` / `getmodelimport` (staging until VerifiedManifest; no live HTTP) |
| `package create\|inspect` | `createbtxpackage` / `inspectbtxpackage` / `verifybtxpackage`. Core v2 unsigned REGTEST. `link` stays magnet analog. Verify is fail-closed. |
| `erasure prepare` | `preparemodelerasure` (per-stripe; global n is not reconstructability) |
| `torrent-status` | `gettorrentsourcestatus` (`btx-torrentd` is not a process) |
| `origin-offer` | `getmodeloriginoffer` (native proxy; presigned GET is not a meter) |
| `transport` | `getevaluatedtransport` (uTP NONSHIPPING; quic false; WAN NOT_RUN) |

R2 AUTO is `SOURCE_FILES` + `STREAM_FILE`. Pieces remain the swarm unit.
FakeS3 is unit-tested. Live HTTPS/R2 is **NOT_RUN** (transport compiled; WAN
not PASS). SCALE huge is **NOT_RUN**. GUI watches are 0.34.8-dev source
(`BUILD_GUI=OFF`). `CLIENT_VERSION_IS_RELEASE=false`. HF/Xet/torrent adapters
are local-native (pin/SSRF/CAS/infohash). They do **not** download from the
public internet in this tree. See
[storage-backends.md](storage-backends.md) and
[cloud-seeding.md](cloud-seeding.md).

```bash
contrib/modelnet/btx-model --json cloud status
contrib/modelnet/btx-model --json follow publisher '<publisher_id>'
contrib/modelnet/btx-model --json events --cursor 0
contrib/modelnet/btx-model --json profile set infrastructure
contrib/modelnet/btx-model --json mirror --publisher '<publisher_id>' --keep-latest 3
```

Existing first-run verbs (unchanged):

```bash
contrib/modelnet/btx-model init
contrib/modelnet/btx-model preview /path/to/dir
contrib/modelnet/btx-model host /path/to/dir
contrib/modelnet/btx-model ls
contrib/modelnet/btx-model ls --incomplete
contrib/modelnet/btx-model show qwen3-local
contrib/modelnet/btx-model files qwen3-local
contrib/modelnet/btx-model path qwen3-local
contrib/modelnet/btx-model search --format gguf --fits --sort size_asc
contrib/modelnet/btx-model check ./incoming/model.safetensors
contrib/modelnet/btx-model pins --type both
contrib/modelnet/btx-model pull qwen3-local
contrib/modelnet/btx-model link qwen3-local ./qwen3.btx
contrib/modelnet/btx-model unhost qwen3-local
contrib/modelnet/btx-model rm-alias qwen3-local
contrib/modelnet/btx-model pause '<job_id>'
contrib/modelnet/btx-model resume qwen3-local
contrib/modelnet/btx-model bounty-draft @./terms.json
contrib/modelnet/btx-model bounty-draft --update '<draft_id>' @./terms.json
```

## Hard no

- Do not collapse prepare/sign/submit. Do not set `auto_pay`.
- Do not run pickle / `.pt` / prompts / cards.
- Do not name operator hostnames in public trees.
- Do not `getmodel` large fixtures into a live attestor datadir.
- Do not put `dn=` (or any query string) on the `btx://` URI.
- Do not pass cloud secrets on argv; use `--credential-ref env:BTX_CLOUD_CREDENTIAL` or `--secret-file`.
