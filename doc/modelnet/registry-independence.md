# Registry independence (0.34.9)

**Status:** 0.34.9-dev. `CLIENT_VERSION_IS_RELEASE=false`. This is the model-plane
resolver: one verified BTX artifact, many disposable origins. It is **not** a
ModelScope clone, **not** a replacement for Hugging Face, **not** a competitor
to OCI/KitOps, and **not** a reason to strip the monetary plane.

Monetary consensus, ExactReplay, wallets, PQ signatures, bounties, and
`automatic_spend_atoms=0` stay. Fetch does not require a wallet or a BTX
balance. The token finances useful infrastructure; it is not an admission
ticket to the infrastructure.

## What this is

A **provider-independent resolution layer for AI artifacts**.

`btx://` plus `VerifiedManifest` answer **what** the artifact is. Origins
answer **where** bytes can be obtained right now. Native BTX publisher
signatures plus OMS/Sigstore/Cosign/OCI attestations answer **who** said it
is authentic. Local capability records answer **whether it can run here**.
Free / private / BTX incentives / bounties / paid hosting answer **how
distribution is funded**.

Hugging Face, hf-mirror, ModelScope, WiseModel, OpenXLab, Modelers, GitCode,
Gitee AI, OpenI, OCI/ModelPack/KitOps, S3/R2, torrents, local disk, and BTX
peers are **origins**, not identities.

A publisher does **not** have to republish into BTX before BTX can fetch the
native artifact. OCI is an origin and an import/export shape. OpenSSF OMS,
Sigstore, Cosign, and OCI attestations are **additional** provenance evidence
slots beside **native BTX publisher signatures**. The import plane **parses and
attaches** those slots (`verified_here=false`); cryptographic verification of
OMS/Sigstore/Cosign is a later gate. BTX aggregates evidence; it is not the
sole CA of AI.

`getmodelimport` / `ImportCoordinator::StatusJson` emit `piece_origins`,
`independent_origin_count`, `min_independent_origins`,
`below_min_independent_origins`, `provenance_evidence`, and a structured
`capability` object (`readiness_target=VERIFIED_FILES`, `inference=false`,
`funded_wallet=false`). Capability here is a local statement, not a GPU
requirement and not an inference run.

## Five questions that must not collapse

| Question | Authority |
|---|---|
| What is it? | SHA-384 + pieces_root → `VerifiedManifest` / `btx://` |
| Who published it? | Native BTX publisher signature; optional OMS/Sigstore/Cosign/OCI/vendor attestation |
| Where can I get it? | `origins[]` (disposable; piece-level routing) |
| Where can I run it? | Local capability evidence, not vendor naming |
| How is distribution funded? | Free / private / BTX incentives / bounties / paid hosting. Fetch does not require a wallet. |

Registry names, OCI tags, and Hugging Face revisions are **not** the BTX
identity. If two registries claim the same version name and the bytes differ,
the identities diverge.

## Piece-level substitution

Acquisition is routing, not URL retry of the whole file.

```
piece 0 → Hugging Face
piece 1 → ModelScope
piece 2 → OCI
piece 3 → local cache
piece 4 → BTX peer
```

Each `Read` extent is typically one `PIECE_SIZE` piece. The first origin that
returns bytes matching the **ChunkLeaf** (or, for a whole-file read, the file
SHA-384) wins. Name equality never substitutes hashes. Whole-file SHA-384 is
applied only when the extent covers the entire file.

## Hard gate (R3-2)

`AcceptVerifiedManifest` re-hashes staged files and recomputes pieces_root
before `PUBLISH_READY`. A registry revision or a caller-supplied id is never
enough.

## Walletless fetch; monetary plane stays

`executemodelimport` / `btx-model fetch` / `btx-model import-plan` must remain
useful with BTX balance 0, no wallet, and no mining. That is a model-plane
property. It does not delete wallets, consensus, ExactReplay, or bounties.

`btx-model resolve @plan.json` dumps origins and the five questions **without**
talking to a chain, a wallet, or the network. `btx-model verify PLAN_ID` is
`getmodelimport`.

Agent door: `contrib/modelnet/btx-model --json`. No web UI. No `artifactd`
that erases BTX.

## Mirror policy

`setmodelmirror` accepts `min_independent_origins` (>= 1). That is a local
keep/follow policy, not a monetary privilege and not consensus. The same
integer may appear on an import plan. Seeing fewer independent origins than
the target **does not fail a walletless fetch**; StatusJson reports
`below_min_independent_origins` as an observation. `getmodelmirror` echoes
`fetch_fails_below_min: false`.

OCI ModelPack import/export (KitOps layout as a first-class package shape,
not only a blob origin) is still later work. OCI blob GET via
`/v2/{repo}/blobs/{digest}` is already an origin.
