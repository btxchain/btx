# R11 — Docs vs executable RPC/CLI (independent review)

**Tree:** `/home/administrator/btx-0.34.7-private`
**Branch:** `feat/0.34.8-modelnet-first-run` (uncommitted doc + code changes on top of `573b4aa4`)
**Scope:** `README.md`, `HUMANS.md`, `AGENTS.md`, `doc/modelnet/*`, `doc/release-notes/release-notes-0.34.8.md`
vs `src/rpc/modelnet.cpp`, `contrib/modelnet/btx-model`, and helper methods.
**Method:** static comparison only. **No compile, no daemon start.** No docs edited (see §5).

Note: the review request named `release-notes-0.34.8.md` at tree root. The file is at
`doc/release-notes/release-notes-0.34.8.md`; there is no root-level copy.

## 1. Ground truth extracted

| Surface | Count | Source |
|---|---|---|
| Registered modelnet RPC methods | 293 | `src/rpc/modelnet.cpp:1856-2153` (`RegisterModelNetRPCCommands`) |
| Registered RPC methods, all planes | 633 | `src/rpc/*.cpp` + `src/wallet/rpc/*.cpp` |
| `btx-model` CLI verbs | 35 | `contrib/modelnet/btx-model:25-60` (`VERBS`) |
| Helper NONSHIPPING/NOT_RUN flags | 8 | `helper.cpp:4770-4776`, `helper_network02.cpp:145-153`, `catalog.cpp:177` |

`btx-model` is a 2493-line Python wrapper at `contrib/modelnet/btx-model`, not a compiled
target. The compiled model-plane binaries are `btx-modeld`, `btx-modelcheck`, `btx-open`,
`btx-capabilityd`, `btx-capability`, `btx-hcpd`, `btx-hosted`
(`src/modelnet/CMakeLists.txt:139-176`).

## 2. Findings

### R11-01 — STALE (high): README claims this tree is a sealed 0.34.7 release build

`CMakeLists.txt:30-34` in this working tree is:

```
set(CLIENT_VERSION_MAJOR 0)
set(CLIENT_VERSION_MINOR 34)
set(CLIENT_VERSION_BUILD 8)
set(CLIENT_VERSION_IS_RELEASE "false")
```

The uncommitted diff moved BUILD 7 → 8 and IS_RELEASE "true" → "false". README was not
fully updated. Six passages still assert the opposite:

| Line | Claim | Actual |
|---|---|---|
| 84-85 | "**v0.34.7** is the shipping tag of this tree. `CLIENT_VERSION` is **0.34.7** with `CLIENT_VERSION_IS_RELEASE=true`." | 0.34.8, `false` |
| 285 | "This tree ships **v0.34.7** with `CLIENT_VERSION_IS_RELEASE=true`." | same |
| 303-304 | "**v0.34.7** is the shipping tag of this tree (`CLIENT_VERSION_IS_RELEASE=true`)." | same |
| 448 | "this tree ships **v0.34.7**" | same |
| 464 | "this tree's shipping tag is **v0.34.7**" | same |
| 1771-1772 | "**v0.34.7 is the shipping tag of this tree** (`CLIENT_VERSION_IS_RELEASE=true`)." | same |

README is internally inconsistent: line 137 and lines 251-253 correctly describe the tree
as **0.34.8-dev**, `CLIENT_VERSION_IS_RELEASE=false`, with 0.34.7 as the last shipping tag.
The distinction that is true and worth preserving is "0.34.7 is the last released **tag**"
vs "this **tree** is a release build". The six passages above assert the second.

Recommend: reword the six passages to "the last shipping tag is v0.34.7; this tree is
0.34.8-dev (`CLIENT_VERSION_IS_RELEASE=false`)", matching line 137.

### R11-02 — STALE (high, machine contract): AGENTS.md contradicts itself on release status

`AGENTS.md:228`, under **Release and session constraints**:

> `CLIENT_VERSION_IS_RELEASE` is **true** for 0.34.7.

`AGENTS.md:5`, header of the same file, was updated on this branch to:

> automation in BTX 0.34.8-dev (`IS_RELEASE=false`). The last shipping tag is **0.34.7**.

The branch diff rewrote the header and left line 228 untouched. This is the file agents are
told to treat as the machine contract, and the stale line sits in the section that governs
push/merge/version-bump behavior, so an agent that reads only that section could conclude it
is operating on a sealed release build. Same fix as R11-01.

### R11-03 — REAL missing docs (medium-high): 67 registered RPCs documented nowhere

67 of the 293 registered modelnet methods appear nowhere in `doc/` (recursive, including
`doc/modelnet/hcp/` and `doc/modelnet/crf/`), `README.md`, `HUMANS.md`, or `AGENTS.md`:

```
accepthcphandoff applyhcpwalletless cacheencryptedmodel cancelbtxcapability
cancelmodelimport createsubscriptionmandate enrollhcpprovider ensurehcplocal
executemodelerasure executemodelstoragemigration exportbtxlock exportbtxpackage
exporthcpstate getbtxcapability getbtxcapabilityevents getbtxresidency
getbtxruntimecapabilities getbtxttctrace gethcpconnectorstatus gethcpreadiness
getmodelbulkstatus getmodelchannel getmodelioexecutor getmodelmirrorstatus
getmodeloriginhealth getmodeloriginstatus getmodeltransfermetrics getmodeluploadinfo
getmodelwatchactions getsubscriptionmandate hcphandle hcphealth importbtxlock
importbtxpackage importhcpstate inspectbtxtensormap listmodelchannels
observebountychain observemodelchannel pairhcpdevice planbtxcapabilityupdate
planhcplocal planmodelstoragemigration prefetchbtxcapability previewhcpprovider
publishmodelimport releasebtxcapability reorgbountychain repairmodel
requestmodelorigin reservemandate reservesubscriptionmandate resumemodelimport
revokehcpdevice revokesubscriptionmandate sethcplocalgrant sethcpreporting
setmodeldiscoverypolicy setmodelstoragepolicy setmodelswarmhealer
settorrentsourcepolicy sleepbtxcapability switchbtxcapability testmodelstorage
unsubscribemodelcollection unsubscribemodelpolicy wakebtxcapability
```

Each carries a one-line help string in `src/rpc/modelnet.cpp` (mostly `BOUNTY_PROXY`), so
the in-RPC help is the only description. Most are diagnostics and are low-risk. The
authority-relevant subset deserves published text because each one grants, accepts, or
reserves something:

- `sethcplocalgrant` — sets the `LocalCapabilityGrant` that `AGENTS.md:51` names as the
  gate on local acquire/run.
- `applyhcpwalletless`, `accepthcphandoff`, `enrollhcpprovider`, `previewhcpprovider`,
  `pairhcpdevice`, `revokehcpdevice` — HCP admission and device pairing.
- `reservemandate`, `reservesubscriptionmandate` — atomic budget reservation (see R11-04).
- `reorgbountychain` — disconnects the last observed tip.

`doc/modelnet/rpc.md` documents no method that does not exist, so this is a coverage gap in
one direction only.

### R11-04 — REAL missing docs (medium, authority): SubscriptionMandate absent from the Authority contract

`AGENTS.md:65-81` (**Authority**) presents exactly one mandate type. It names
`createagentmandate` / `getagentmandate` / `revokeagentmandate` and cites
`contrib/modelnet/bounty/schemas/AgentMandate.schema.json` as the "Required shape".

A second budget-bearing mandate type is registered and is not in that section:

| RPC | Help text (`src/rpc/modelnet.cpp`) |
|---|---|
| `createsubscriptionmandate` | :1470 "Finite SubscriptionMandate for future objects. Distinct from AgentMandate." |
| `getsubscriptionmandate` | :1471 |
| `revokesubscriptionmandate` | :1472 |
| `reservesubscriptionmandate` | :1473 "Atomic SubscriptionMandate reservation. Cannot exceed budget." |

It is a real limit-carrying object, not a label: `src/modelnet/subscription_mandate.cpp`
validates `per_action_principal_limit_atoms` and `total_principal_limit_atoms` (:334-339),
enforces `terms.principal_atoms > mandate.per_action_principal_limit_atoms` (:649), and
reports `wallet_signed=false` (:480-482).

Two concrete gaps:

1. **No schema.** `contrib/modelnet/bounty/schemas/` has `AgentMandate.schema.json` but no
   `SubscriptionMandate.schema.json`. AGENTS.md's "Required shape" pattern has no analog for
   the second type.
2. **The reservation RPC is never named.** The Authority table's "Atomic reservations /
   `max_concurrent_reservations` (1-32). Concurrent RPCs must not over-reserve" row
   (`AGENTS.md:75`) describes a constraint, but `reservemandate` — the RPC that performs it —
   is not named anywhere in the docs.

This is a gap, **not** a false claim. The docs never assert a SubscriptionMandate schema
exists, and the concept is disclosed honestly elsewhere:
`doc/modelnet/watches.md:37` marks `FUND_WITH_MANDATE` as "**Not** a `follow` action.
Requires a distinct `SubscriptionMandate` on the wallet plane (`wallet_signed=false` is
intentional)", and `doc/modelnet/rpc.md:740` and the 0.34.8 notes repeat it. The gap is that
the **machine contract** an agent is told to obey omits it.

### R11-05 — STALE (minor): AGENTS.md verb list omits 2 of 35 CLI verbs

`AGENTS.md:114-121` enumerates the `btx-model` verbs but omits `init` and `open`
(`VERBS`, `contrib/modelnet/btx-model:25-60`). Both are documented elsewhere —
`init` in `first-run.md:58`, `agent-recipes.md:87`, `rpc.md:144`; `open` in
`agent-recipes.md:64,99` and `first-run.md:284,379` — so this is an AGENTS.md-only omission.
All 35 verbs have at least one mention across the doc set.

### R11-06 — STALE (minor, naming): `bitcoin-qt` is not a target in this tree

`doc/modelnet/rpc.md:738` says "GUI is source-only (`BUILD_GUI=OFF`; `bitcoin-qt` was not
built here)". The 0.34.8 release notes use the same phrasing ("do not claim `bitcoin-qt` was
built"). The CMake GUI target is `btx-qt` (`CMakeLists.txt:100`, `src/qt/CMakeLists.txt:402`);
`bitcoin-qt` is not a target here. The intent (no GUI was built) is correct and
`BUILD_GUI` does default to `OFF`; only the binary name is stale. Every other doc reference
uses `btx-qt` correctly.

### R11-07 — Thin docs (minor)

The `erasure` CLI verb has a single mention across the whole doc set, the thinnest of the 35.
`import-plan`, `package`, `torrent-status`, `origin-offer`, and `transport` have 3-4 each.

## 3. No FALSE_POSITIVE found

Every NONSHIPPING / NOT_RUN flag the code emits is disclosed in the docs. I found no case of
docs claiming a NONSHIPPING capability ships.

| Flag | Code | Doc disclosure |
|---|---|---|
| `utp` = NONSHIPPING | `helper.cpp:4770`, `helper_network02.cpp:145`, `catalog.cpp:177` | `rpc.md:772`, notes Round 5, `AGENTS.md:52` |
| `content_defined_dedup` = NONSHIPPING | `helper.cpp:4772`, `helper_network02.cpp:147` | `rpc.md:776` ("CDC NONSHIPPING") |
| `erasure_64_80` = NONSHIPPING | `helper.cpp:4773`, `helper_network02.cpp:148` | notes Round 5 |
| `quic` = false | `helper.cpp:4771`, `catalog.cpp:176` | `AGENTS.md:52` ("QUIC remains NONSHIPPING"), `rpc.md:772` |
| `btx_torrentd_process` = false | `helper.cpp:4775`, `catalog.cpp:178` | `rpc.md:767,779` |
| `catalog_10m` = NOT_RUN | `helper_network02.cpp:149` | notes Round 5 |
| `live_hf_http` = false | `helper_network02.cpp:151` | notes Round 4/5, `HUMANS.md:139` |
| `live_r2_wan` = NOT_RUN | `helper_network02.cpp:152` | `rpc.md:772,779`, `HUMANS.md:139` |

One apparent conflict resolves in the docs' favor. `HUMANS.md:127` says "Erasure repair is
**per stripe**" while `erasure_64_80` is NONSHIPPING. These are different claims: the
NONSHIPPING flag is the specific 64/80 Reed-Solomon rate, and per-stripe sufficiency is
implemented — `src/modelnet/erasure_store.cpp:189` reads "Sufficiency is per stripe via
`ErasureManifestReconstructable`. Never n," which is exactly what `rpc.md:766` claims
("Per-stripe reconstructability. Global `n` is **not** sufficiency"). Not a defect.

## 4. Verified accurate (no action)

Checked and correct, listed so a later lane does not re-audit:

- **`automatic_spend_atoms = 0` holds.** `PackageAutomaticSpendAtoms()` →
  `AutomaticSpendAtoms()` (`package_economy.cpp:228-231`). Every non-test occurrence writes
  0. The only nonzero values are negative tests asserting rejection
  (`modelnet_jit_tests.cpp:471`, `modelnet_jit_safety_tests.cpp:194,245,362`,
  `modelnet_jit_ensure_tests.cpp:157,526`). No dangerous spending claim found anywhere in
  the doc set.
- **"34 typed REST ops"** (`AGENTS.md:42`): `src/modelnet/hcp/schemas/openapi.yaml` has
  exactly 34 `operationId`s and 34 paths. HUMANS.md's "original **34** HCP operations"
  matches.
- **`rpc-catalog.json`**: all 60 entries are registered RPCs; zero phantom methods. Its
  `status` is `PROPOSED_CONTRACTS_NOT_IMPLEMENTATION_CLAIM`, which is honest.
- **HTLC RPC names** (`AGENTS.md:58`): `buildhtlcclaim` / `buildhtlcrefund` are real
  wallet-plane RPCs (`src/wallet/rpc/wallet.cpp:1455-1456`), correctly cited for the
  monetary path; `buildmodelhtlcclaim` / `buildmodelhtlcrefund` are the modelnet pointers
  (`rpc/modelnet.cpp:1966-1967`). Not a naming error.
- **Links**: all 14 doc targets referenced from HUMANS.md resolve, including
  `doc/hosted/HCP_OPERATOR_NOTES.md` and `audit/hcp-authority-matrix.md`.
- **Recipes**: all 8 files named in the 0.34.8 notes exist in `contrib/modelnet/recipes/`
  (`watch-status.json`, `bounty-update.json`, `bounty-delete.json`, `pause.json`,
  `cloud-status.json`, `follow-publisher.json`, `events.json`, `infra-profile.json`).
- **assumeutxo** (`README.md:91-95`): height 219000 is pinned in
  `src/kernel/chainparams.cpp`; 199299 and 199300 are absent from the pin table, matching
  the "removed / must resync" claim.
- **Options**: `-modelwatch=<dir>` (`init.cpp:650`) and `-modelstorage=<size>` with `auto`
  default (`init.cpp:641`, `:4103`) exist as documented. `BUILD_GUI` defaults `OFF`
  (`CMakeLists.txt:100`).
- **`getmininginfo.first_run`**: `ready_to_mine`, `ibd`, `blocks`, `peer_count`, `min_peers`,
  `connections_total`, `network_active`, `verificationprogress`, `tip_age_s`,
  `has_warnings`, `one_liner`, `recommended_action` all present
  (`src/rpc/mining.cpp:6699-6744`, :6858-6874). `getsetupstatus` is registered
  (`rpc/modelnet.cpp:1925`).
- **`hostmodel` is the alias of `importmodel`**: help text confirms "Alias of importmodel:
  pin, demand-seed, and publish a signed search card" (`rpc/modelnet.cpp:589`), with
  `publish` defaulting true (:594) — matches the notes' `{"publish":false}` opt-out.
- **searchmodels filters**: `format`, `quantization`, `family`, `architecture`,
  `min_size_bytes`, `max_size_bytes`, `min_provider_count` all exist
  (`search.cpp:523,554,565`, `search.h:130`), and the CLI flags howto.md names
  (`--format`, `--fits`, `--sort`) exist (`btx-model:125-131,852-864,953,969`).
- **Models page tabs** (`HUMANS.md:172-175`): all 10 named tabs (Latest, Nearly Funded,
  Available, Rare, Just Released, Local, Releases, Publishers, Collections, Bounties) appear
  in `src/qt/forms/modelnetpage.ui`.

The 0.34.8 release notes are the most accurate file in scope. Their "Honest status"
paragraphs (Rounds 4 and 5) correctly hedge FakeS3-vs-live-R2, `BUILD_GUI=OFF`,
`wallet_signed=false`, uTP/QUIC, and the 10M catalog.

## 5. Editing decision

**No docs edited.** The lane permits patching a single dangerous false sentence about
spending or authority. The two high-severity defects (R11-01, R11-02) are false claims about
**release status**, not about spending or authority, so they fall under "prefer reporting".
The `automatic_spend_atoms = 0` invariant and every NONSHIPPING disclosure check out, so no
dangerous spending or authority sentence was found to patch.

R11-01 and R11-02 need an operator decision anyway, because the correct wording depends on
whether 0.34.8-dev is intended to stay in this tree or the CMakeLists bump is meant to be
reverted.
