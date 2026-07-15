# BTX Inscription & Content-Storage Elimination Plan

Status: **DRAFT SPEC** — not yet scheduled to a release. Target activation
height and release train are filled in at review sign-off (see §9).

## 0. Purpose and scope

BTX is a financial base layer: post-quantum value transfer (witness v2 P2MR),
custody/vault covenants (CTV/CSFS/CLTV/CSV/multisig leaves), atomic swaps/OTC
(HTLC leaves), a lattice shielded pool (winding down at the 125000 sunset), and
the WBTX bridge. **Non-financial data storage — inscriptions, ordinals-style
envelopes, NFT/"artifact" meta-protocols, BRC-20-style token layers, arbitrary
content and file storage — is out of scope for the chain and is to be
eliminated at both the relay (policy) and block (consensus) layers.**

This plan follows the codebase's established rule-change discipline used by the
shielded sunset (`doc/shielded_sunset_125000_plan.md`): a **buried flag-day
height** with an `IsXxxActive(height)` helper in `src/consensus/params.h`, set
per-network in `src/kernel/chainparams.cpp`, and enforced identically in the
**three lockstep locations** — mempool policy (`src/policy/policy.cpp`), the
block-template builder (`src/node/miner.cpp`), and block consensus
(`src/validation.cpp`). A rule added to fewer than all three produces invalid
templates or relay/mine divergence.

### 0.1 What "eliminate" means here (and its hard limit)

Two honest boundaries frame every decision below:

1. **Already-committed data is permanent.** Any bytes already in the chain
   (including any OP_RETURN meta-protocol records already committed, §2) cannot be removed;
   the chain is immutable. Elimination means (a) preventing *new* embeddings
   after the activation height, and (b) removing BTX's own tooling that
   *renders/decodes* meta-protocol content, so first-party explorers, wallets,
   and RPC do not surface it. We can starve the meta-protocol of new data and
   refuse to display it; we cannot rewrite history.

2. **Steganography can be raised in cost but never fully banned.** Value must
   travel *somewhere* — to a 32-byte P2MR program, in an amount field, in a
   PQ signature. A determined actor can grind a few bits into a pubkey-hash or
   an amount's low bits. No consensus rule stops that without breaking money.
   The objective is therefore **structural**: make the chain unusable as a
   *data-availability layer for a protocol* — no cheap, high-bandwidth,
   reliably-recoverable channel that an indexer can standardize on. Every
   inscription/NFT/token meta-protocol depends on such a channel; remove the
   channel and the meta-protocol cannot exist, even though a handful of
   steganographic bits per tx remain theoretically possible and economically
   useless.

## 1. Current state: what BTX already enforces

BTX is **not** a stock Bitcoin/Knots relay-policy chain. It already ships a
genesis-active consensus output filter, which materially narrows the design.

### 1.1 Consensus output filter (genesis-active) — `CheckReducedDataOutputLimits`

`src/validation.cpp:9685-9720`, invoked from `CheckBlock`
(`src/validation.cpp:9790-9793`). Active when
`consensus_params.fReducedDataLimits` is true. For every `tx.vout`:

- OP_RETURN output (`scriptPubKey[0] == OP_RETURN`): rejected
  `bad-txns-opreturn-size` if `size > nMaxOpReturnBytes` (default **83**,
  `src/consensus/params.h:133`).
- Non-OP_RETURN output: rejected `bad-txns-scriptpubkey-size` if
  `size > nMaxTxoutScriptPubKeyBytes` (default **34**,
  `src/consensus/params.h:134`).
- If `fEnforceP2MROnlyOutputs`: every non-OP_RETURN output must be witness v2
  with a 32-byte program (`is_p2mr_output`), else `bad-txns-nonp2mr-output`.

Network activation (`src/kernel/chainparams.cpp`): mainnet (`161-162`),
testnet/signet-class networks (`534-535`, `716-717`, `928-929`) have **both**
flags true. Regtest (`1089-1090`, `1428-1429`) has `fReducedDataLimits=true`,
`fEnforceP2MROnlyOutputs=false` so tests can build arbitrary outputs.

**Consequence — several classic vectors are already dead at consensus on
mainnet:**

- **Ordinals witness envelopes via taproot outputs**: you cannot *create* a
  witness v1 (taproot) output — `fEnforceP2MROnlyOutputs` forces every
  non-OP_RETURN output to be a 32-byte v2 P2MR program. No v1 outputs exist
  (genesis-active), so no taproot script-path reveal is ever reachable. The
  single most dangerous inscription vector on Bitcoin does not apply to BTX.
- **Bare multisig / bare pubkey / OLGA-style fake-program stuffing**: these are
  non-P2MR, non-OP_RETURN outputs and are consensus-rejected by the 34-byte cap
  + P2MR-only rule. UTXO-bloat stamping is not possible.
- **Large arbitrary OP_RETURN**: consensus-capped at 83 bytes (not merely
  policy-capped, unlike upstream Bitcoin).

### 1.2 Relay policy (already hostile) — `src/policy/policy.cpp`

- `IsStandard` (`498-516`): only `WITNESS_V2_P2MR` outputs and a single
  size-bounded `NULL_DATA` (OP_RETURN ≤ `max_datacarrier_bytes`, default 83)
  are relay-standard. Line 515: `return whichType == WITNESS_V2_P2MR;`.
- P2MR witness leaf **allowlist** — `ParsePolicyP2MRLeafScript`
  (`policy.cpp:818-1075`): a P2MR spend is standard only if its revealed leaf
  parses to a known *financial* template (`CHECKSIG_{MLDSA,SLHDSA}`, `MULTISIG`,
  `CLTV/CSV/CTV` covenant variants, `CSFS_*`, `HTLC_*`, delegation, refund).
  Arbitrary data-push leaves → `UNKNOWN` → `p2mr-leaf-script` reject.
- `DatacarrierBytes` envelope filter (`src/script/script.cpp:337-389`, invoked
  `validation.cpp:4668-4676`): counts ord-style `OP_FALSE OP_IF … OP_ENDIF`
  blocks, `<data> OP_DROP`, and OLGA/"stamp" P2WSH payloads; rejects
  `txn-datacarrier-nonstandard` / `-exceeded`.
- Parasite/token knobs: `-rejectparasites` default **true** (cat-21 `nLockTime==21`
  reject, `policy.cpp:559`); `-rejecttokens` default **false** (runes
  `OP_RETURN OP_13` and OLGA rejects, `policy.cpp:617,629`);
  `-permitbaremultisig`/`-permitbarepubkey` default false.

### 1.3 The gap that remains

Relay policy is strong but **operator-overridable** (`-acceptnonstdtxn`,
`-acceptnonstddatacarrier`, `-corepolicy` at `init.cpp:938-962`, or simply a
miner including a tx directly in a template). The genesis consensus filter
(§1.1) closes the *output* vectors but leaves **four channels** open to a
cooperating miner or a permissive relay path, plus one that is legal by design:

| # | Channel | Where | Consensus-open? | Max bytes |
|---|---|---|---|---|
| A | **OP_RETURN ≤ 83 B** (the meta-protocol marker lane) | any tx output | **legal by design** | 83 |
| B | **P2MR witness leaf** arbitrary pushes (envelope / `OP_DROP` / false-branch) | spend witness | yes (relay-blocked only) | ~11 000 leaf / 10 000 per push / 1 MB stack |
| C | **CSFS/HTLC message** element | spend witness | yes; **relay-standard** ≤520 B/input | 520 × inputs |
| D | **Shielded proof-payload gap/trailing bytes** + memo/ciphertext | shielded serialization | pre-sunset only; post-sunset drains to zero | see §4 |
| E | **Coinbase scriptSig** | coinbase | consensus 2–100 B, miner-only | 100 |

Channel A is the one actually in use (§2). Channels B, C, E are latent and are
closed by consensus rules below. Channel D is **already handled by the 125000
shielded sunset** (no new shielded value can enter; the pool only drains) — a
dedicated pillar for it was considered and rejected as not worth the added
consensus surface on a retiring subsystem (§4). So the plan ships **five**
consensus/relay changes (Pillars 1, 2, 3, 5, 6); Pillar 4 is documented but
carries no code.

## 2. The relevant technique: OP_RETURN-anchored meta-protocols (channel A)

The meta-protocol pattern that motivates this plan does **not** use an ordinals
witness inscription (which the genesis P2MR-only filter already makes
impossible, §1.1). It uses a **small commitment in one standard OP_RETURN
output**, of the general form: a short magic/version prefix, an operation code
(e.g. "mint"), a collection/item identifier, a flags byte, and a **32-byte hash
of an off-chain record**. The heavy content (images, metadata) lives off-chain
(IPFS/HTTP or an indexer); only the ≤32-byte commitment is on-chain.

Why such a marker sails through today's filters and what that implies:

- A well-formed ≤83-byte OP_RETURN passes every existing policy check — it is a
  single OP_RETURN, within the datacarrier size, not a runes/cat-21 pattern, and
  rides alongside normal monetary outputs. It is standard **and** consensus-valid
  by the current rules.
- **The node has no awareness of the meta-protocol.** Consensus and policy see an
  ordinary OP_RETURN; the "collection", "soulbound", gating, and any carrier-UTXO
  semantics are enforced **entirely in the application layer** (wallets and
  explorers), not on-chain.

**Design implication.** This class of meta-protocol needs only a *tiny
commitment* (a 32-byte hash) on-chain — exactly the payload the 83-byte
OP_RETURN lane was meant to allow for legitimate uses. It is the general shape of
every modern content meta-protocol (BRC-20, runes, ordinals number-space): the
heavy content is off-chain or in an indexer; the chain only anchors a small,
recoverable, standardized marker. **Therefore the decisive move is to remove the
small-marker channel, not to hunt for big blobs.** A chain with no reliable,
uniform, indexable commitment channel cannot host a token/NFT meta-protocol.

## 3. Design principle: structure over size

BTX has enormous *legitimate* non-monetary-looking bytes: ML-DSA-44 signatures
(2420 B), SLH-DSA (7856 B), 1312-B PQ pubkeys pushed inside leaves, 51–100 KB+
lattice proofs, 4096-B note ciphertext. **Any size-based rule is fatal** — it
either breaks money or fails to stop data. Every rule below discriminates by
**structure** (is this byte-region the operand of a financial opcode / a
verifying proof, or is it free-form?), never by raw length. The authoritative
"what must stay spendable" list is the P2MR leaf allowlist
(`policy.cpp:916-1074`); consensus rules are written to *match* it, promoting
the existing relay allowlist to consensus rather than inventing new shapes.

## 4. The plan: five shipped pillars (Pillar 4 rejected)

New flag-day height, provisional name `nContentEliminationHeight` (constant
`BTX_CONTENT_ELIMINATION_HEIGHT`, value set in §9), with helper
`IsContentEliminationActive(height)` in `src/consensus/params.h` modeled on
`IsShieldedSunsetActive` (`params.h:509-514`). Pillars 1, 2, 3, and 5 gate their
consensus rules on it; Pillar 6 is immediate relay/RPC hardening. Pillar 4 was
considered and rejected (see below) and ships no code.

### Pillar 1 — Close the OP_RETURN meta-protocol channel (kills channel A)

This is the load-bearing pillar. At height ≥ H, in
`CheckReducedDataOutputLimits` (`validation.cpp:9698-9706`) and mirrored in
policy (`IsStandard`, `policy.cpp:508-513`) and the miner
(`miner.cpp:60-83,386-390`):

- **Non-coinbase transactions: no OP_RETURN outputs at all.** Reject
  `bad-txns-opreturn-forbidden`. There is **no financial dependency** on
  transaction-level OP_RETURN in BTX (wallet's only emitter is the
  `createrawtransaction {"data":…}` path, `rpc/rawtransaction.cpp:238`, which is
  non-financial and is removed in Pillar 6). This eliminates every
  OP_RETURN-anchored meta-protocol at consensus.
- **Coinbase exemption, structurally constrained.** The coinbase carries the
  mandatory **witness commitment**, a 38-byte OP_RETURN
  (`MINIMUM_WITNESS_COMMITMENT = 38`, `consensus/validation.h:18`;
  `GetWitnessCommitmentIndex`, `validation.cpp:9633`). The coinbase may contain
  **exactly the witness-commitment output(s)** — an OP_RETURN whose script
  matches the `0x6a24aa21a9ed…`(+optional) witness-commitment prefix and is
  ≤ the commitment length — and no other OP_RETURN. Any other coinbase OP_RETURN
  → `bad-cb-opreturn`. This preserves block production (which requires the
  commitment) while denying miners a coinbase data channel beyond the 100-byte
  scriptSig handled in Pillar 5.
- Because the witness-commitment output is now the *only* allowed OP_RETURN, the
  `nMaxOpReturnBytes` knob is retired for non-coinbase and pinned to the
  commitment length for coinbase; keep the field for wire/serialization
  compatibility but stop honoring operator overrides at/after H.

Rationale over "shrink to 0 bytes": a 0-byte-data OP_RETURN is still a uniform,
detectable marker output that an indexer can key on (its mere presence, plus an
accompanying small carrier UTXO, can encode a mint — the marker output is as much
a signal as its payload). Forbidding the output type outright removes the marker,
not just its payload.

### Pillar 2 — Promote the P2MR leaf allowlist to consensus (closes channel B)

Today a cooperating miner can include a P2MR spend whose revealed leaf is a
valid merkle-committed script (passes `VerifyP2MRCommitment`,
`interpreter.cpp:2366`) but is stuffed with data — an `OP_FALSE OP_IF <data>
OP_ENDIF` envelope, `<data> OP_DROP` chains, or oversized junk pushes — up to
`MAX_P2MR_SCRIPT_SIZE = 11000` / `MAX_P2MR_ELEMENT_SIZE = 10000` /
`MAX_P2MR_STACK_BYTES = 1_000_000` (`script.h:88-96`). Relay blocks it
(`ParsePolicyP2MRLeafScript`), consensus does not.

At height ≥ H, enforce leaf-type conformance **in consensus** during P2MR script
validation (`interpreter.cpp` P2MR path around `2338-2374`, gated by
`IsContentEliminationActive`):

- The revealed leaf script must parse to one of the allowlisted financial
  templates — reuse the *exact* `ParsePolicyP2MRLeafScript` classifier so
  consensus and policy cannot diverge; move it (or a consensus-safe twin) from
  `policy.cpp` to a shared location (`src/script/pqm.cpp`) callable from the
  interpreter. Non-conforming leaf → script failure
  `SCRIPT_ERR_P2MR_LEAF_NONFINANCIAL`.
- Enforce the per-position element sizes the allowlist already specifies:
  signature elements exactly `MLDSA44_SIGNATURE_SIZE=2420` /
  `SLHDSA128S_SIGNATURE_SIZE=7856` (+ empty-sig placeholders), pubkey pushes
  1312/32 via the canonical `ParseP2MRPubkeyPush` (`pqm.cpp:42-75`), leaf bytes
  ≤ template maximum. This bans free-form pushes structurally while whitelisting
  every real signature/pubkey/covenant operand.

Effect: the witness leaf stops being a data channel; only bytes that are
operands of financial opcodes survive. This is the structural (not size-based)
rule §3 demands — a 2420-byte push is fine *because it is an ML-DSA signature in
a CHECKSIG leaf*, while a 2420-byte push in an `OP_IF` false branch is rejected.

**Deployment caution.** Because pre-H P2MR spends were consensus-permitted for
non-allowlisted leaves, this must be a clean flag-day gate: nodes reject
non-conforming leaves only for spends **in blocks at height ≥ H**. Existing
UTXOs whose committed leaves are non-financial remain spendable *only* if their
leaf conforms; a small set of pathological pre-existing commitments could become
unspendable. Survey UTXO set before setting H (§9) and, if any legitimate custody
UTXO would be caught, add a narrow grandfather exemption keyed on commitment
hash.

### Pillar 3 — Constrain the CSFS/HTLC message element (closes channel C)

The one genuinely arbitrary, **relay-standard** witness blob is the CSFS signed
message / HTLC preimage element, allowed up to `MAX_SCRIPT_ELEMENT_SIZE = 520`
bytes per input (`policy.cpp:1012,1029,1055`). 520 B/input across many inputs is
a usable covert channel.

At height ≥ H, both policy and consensus:

- **HTLC preimage**: require the element be exactly the hash-preimage length the
  leaf's hashlock demands (32 B for SHA-256/HASH256, 20 B for HASH160). A
  preimage is validated by `OP_SHA256 … OP_EQUAL`; its length is fully
  determined by the hash function, so a correctly-sized preimage carries no free
  bytes. Reject other lengths → `p2mr-htlc-preimage-size`.
- **CSFS message**: bind the message to a structured, bounded form. Options,
  in preference order: (a) require the CSFS-signed message be a 32-byte hash
  (oracle attestations and delegation tags are hashes in the existing
  templates); (b) if variable-length oracle messages are a required product
  surface, cap at a small structural bound (e.g. 64 B) **and** require the
  message be the exact bytes the signature commits to (it already must verify
  under `OP_CHECKSIGFROMSTACK`, so it is not free — but 520 B of "signed data"
  is still 520 B of attacker-chosen content). Confirm with the CSFS/delegation
  product owners which oracle message shapes are real before fixing the bound.

### Pillar 4 — Shielded proof-payload coverage — **CONSIDERED AND REJECTED**

Channel D (shielded serialization) was originally slated for a consensus rule
requiring full contiguous `proof_payload` coverage
(`ProofShardCoverageIsCanonical`, `v2_bundle.cpp:3537-3559`) to reject
inter-shard gap and trailing "filler" bytes. **This pillar is dropped.** It is
not worth its cost on a sunsetting, outflow-only pool. The reasoning:

- **The sunset, not this pillar, kills the shielded data channel.** The
  high-bandwidth shielded vector is "mint a fresh note/credit and stuff opaque
  bytes into it." That is already consensus-disabled at the 125000 sunset
  (`BTX_SHIELDED_POOL_CREDIT_DISABLE_HEIGHT`): no new shielded value may ENTER,
  the pool only drains. The credit freeze provides this, not any new rule here.
- **The content-elimination height is *after* the sunset.** H (≈165000, §9) is
  ≥ 125000, so this pillar would only ever operate in the outflow-only regime.
  The only transactions it could constrain are exits, recovery exits, and
  bridge/settlement — all carrying large, verifying proofs.
- **The residual channel is expensive, low-bandwidth, temporary, and
  self-closing.** Padding an exit proof's `proof_payload` costs the 51–100 KB
  proof build, the `MIN_SHIELDED_RELAY_FEE_PREMIUM = 5000` sat premium, and the
  240k per-block verify budget, for a few unspanned bytes — on a pool that is
  draining to zero and taking this channel with it.
- **It does not even close channel D.** The opaque `EncryptedNotePayload`
  `ciphertext` (≤4096) and `memo` (≤512) that ride on an exit's shielded *change*
  note are validated by length only and have no structural fix (they are
  encryption blobs). The coverage rule cannot touch them, so the part of the
  shielded surface still open post-sunset is the part this pillar can't address.
- **It cuts against the sunset's own principle.** `doc/shielded_sunset_125000_plan.md`
  commits to the "smallest consensus exception surface — freeze the state
  machine." Adding *new* consensus logic to the shielded proof-check path is
  added review/risk surface on a subsystem being retired, for a benefit that
  expires on its own.

If any residual coverage is ever wanted, it should be a **relay-only**
standardness check (zero consensus surface on the frozen subsystem), not a
consensus rule — but given the pool is winding down, even that is optional. No
code ships for this pillar; channel D is handled by the existing 125000 credit
freeze, and its irreducible opaque-ciphertext remainder disappears when the pool
drains.

### Pillar 5 — Tighten the coinbase scriptSig (closes channel E)

Coinbase scriptSig is consensus-bounded 2–100 bytes (`tx_check.cpp:77`),
miner-only. The BIP34 height prefix + a modest extranonce need well under 100
bytes. At height ≥ H, in `CheckTransaction`/coinbase validation: require the
coinbase scriptSig to begin with the canonical BIP34 serialized height push and
limit the trailing bytes to a bounded extranonce (e.g. ≤ 40 B total scriptSig).
Reject `bad-cb-scriptsig-content`. This removes ~90 bytes/block of miner data
channel without affecting mining ergonomics. Lowest priority — miner-only,
low-bandwidth — but included for completeness of "no content channels."

### Pillar 6 — Immediate relay hardening + first-party tooling cleanup (no fork)

Ship ahead of / alongside the fork; effective immediately at the relay and
application layer, no activation height:

**Relay defaults (`src/policy/policy.h`, `src/node/mempool_args.cpp`,
`src/init.cpp`):**
- `-rejecttokens` default `false → true` (`policy.h:88`) and hard-enable at H —
  kills runes/OLGA relay now.
- `-datacarrier` effectively off for non-coinbase: set standard OP_RETURN
  acceptance to reject at relay ahead of the consensus rule, so the mempool
  stops propagating OP_RETURN meta-protocol mints before H.
- Remove the `-corepolicy` escape hatch's ability to re-loosen datacarrier /
  bare-multisig / parasite filters (`init.cpp:938-962`) on mainnet, and drop
  `-acceptnonstddatacarrier` / `-permitbaredatacarrier` mainnet effect. (These
  are relay-only; they never affect the consensus rules in Pillars 1–5, which by
  design **cannot** be disabled by node operators — the correct posture.)

**First-party tooling (removes rendering, per §0.1(1)):**
- Node RPC/REST/ZMQ (`rpc/rawtransaction.cpp`, `core_write.cpp`, `rest.cpp`,
  `src/zmq/`) still decode witness/script to hex (needed for real txs) — leave
  raw decode intact, but **remove any meta-protocol-aware decode or convenience
  fields** if present (none found in `src/`; confirm none is added). Do not build
  meta-protocol indexers into the node.
- `createrawtransaction`/`createpsbt` `{"data":…}` OP_RETURN output builder
  (`rpc/rawtransaction.cpp:238`): remove for non-coinbase, so first-party
  tooling cannot mint OP_RETURN payloads. (Wallet has no other data-embedding
  RPC; `permitbaredatacarrier` already false.)
- First-party explorer / wallet reference clients
  (`doc/browser-wallet-backend.md`, `doc/btxwallet-browser-node-interop.md`):
  ship a reference explorer/indexer posture that **does not detect or render**
  any meta-protocol magic — treat such outputs as opaque/absent. This is the
  concrete answer to "so future clients, explorers etc. cannot even show it":
  once new mints are consensus-forbidden (Pillar 1) and first-party clients
  refuse to interpret the pre-H records, the meta-protocol has no data-availability
  path forward and no first-party surface. Independent third-party explorers are
  outside our control and can still render the frozen pre-H set; document this
  limit publicly rather than implying we can force them.

## 5. Vector → pillar coverage matrix

| Vector | Pre-plan status | Pillar | Post-plan status |
|---|---|---|---|
| Taproot ord envelope (v1 output) | already dead (§1.1) | — | dead |
| Bare multisig / pubkey / OLGA stamp | already dead (§1.1) | — | dead |
| OP_RETURN meta-protocol marker | **legal ≤83 B** | 1 | non-coinbase forbidden; coinbase = commitment only |
| P2MR witness leaf data pushes | relay-blocked, consensus-open | 2 | consensus leaf allowlist |
| CSFS/HTLC message blob (≤520 B) | relay-standard | 3 | hash/bounded structural form |
| Shielded proof-payload gap bytes | consensus-open pre-sunset; drains post-sunset | 4 (rejected) | left to the 125000 sunset; no new consensus rule |
| Shielded ciphertext/memo | length-only | 125000 sunset | no new value enters; pool drains to zero |
| Coinbase scriptSig (≤100 B) | consensus, miner-only | 5 | BIP34 + bounded extranonce |
| Steganography in program/amount bits | irreducible | — | out of scope (§0.1(2)) |
| Relay overrides / meta-protocol tooling | operator-loosenable / n/a | 6 | hardened / removed |

## 6. What must NOT break (financial-surface guardrails)

Every pillar was written against this list; reviewers must re-verify each edit
against it (constants and validators from the financial-surface survey):

- **P2MR spend-to output**: keep `nMaxTxoutScriptPubKeyBytes ≥ 34` and the
  witness-v2/32-byte exemption (`validation.cpp:9689,9708`). Exact fit, zero
  margin — never reduce below 34.
- **PQ signatures/pubkeys in witness**: whitelist exact sizes 2420/7856 sig,
  1312/32 pubkey (`pqkey.h:18-24`); leaf ≤ `MAX_P2MR_SCRIPT_SIZE=11000`, element
  ≤ `MAX_P2MR_ELEMENT_SIZE=10000` (`script.h:88,93`). Pillar 2 must whitelist
  these, not cap them.
- **Custody/covenant/HTLC leaves** (`src/script/pqm.cpp` builders; `MRLeafType`
  `descriptor.cpp:1642`): large PQ pubkey pushes are *operands*, not data — a
  naive "ban large/unexecuted pushdata" rule would make every vault unspendable.
  Pillars 2–3 key off the allowlist, not push size.
- **Shielded proofs / exits**: the shielded serialization
  (`TX_NO_WITNESS_WITH_SHIELDED`) is a separate branch, untouched by the vout
  OP_RETURN filter and by every consensus rule in this plan — no shipped pillar
  touches shielded code. The pool is outflow-only after the 125000 sunset and
  drains to zero, so exits, recovery exits, and WBTX bridge/settlement
  (`V2_SETTLEMENT_ANCHOR`/`V2_EGRESS_BATCH`, carrying proof/receipt bytes in
  `proof_payload`) are entirely unaffected. (This is why Pillar 4 was dropped —
  §4.)
- **Coinbase witness commitment**: OP_RETURN cap must stay ≥
  `MINIMUM_WITNESS_COMMITMENT = 38` for the coinbase (Pillar 1 exempts it
  explicitly). Do not forbid coinbase OP_RETURN wholesale or block production
  stops.

## 7. Implementation checklist (three-location lockstep)

These reflect what shipped (Pillars 1, 2, 3, 5 consensus + Pillar 6 relay):

1. **Consensus params** — `src/consensus/params.h`:
   `int32_t nContentEliminationHeight{INT32_MAX};` + `bool
   IsContentEliminationActive(int32_t) const` (modeled on `params.h:509-514`).
2. **Chainparams** — `src/kernel/chainparams.{h,cpp}`, `src/chainparams.cpp`,
   `src/chainparamsbase.cpp`: `BTX_CONTENT_ELIMINATION_HEIGHT` set for the five
   production-class networks, disabled by default on regtest with a
   `-regtestcontenteliminationheight` override for tests.
3. **Block consensus (Pillars 1 & 5)** — `src/validation.cpp`
   `CheckContentEliminationRules`, called from `ContextualCheckBlock` (has
   `nHeight`): forbid non-coinbase OP_RETURN, restrict coinbase OP_RETURN to the
   witness commitment, bound the coinbase scriptSig.
4. **Block consensus (Pillars 2 & 3)** — `src/validation.cpp` `ConnectBlock`:
   require `IsWitnessStandard(tx, view, …)` for every non-coinbase tx once
   active. This **reuses the existing relay classifier** rather than moving it
   into the script library — `validation.cpp` already depends on policy, and
   reusing the one implementation guarantees consensus and relay cannot diverge.
5. **Relay policy (Pillar 6)** — `src/policy/policy.h` (`DEFAULT_ACCEPT_DATACARRIER`
   off, `DEFAULT_REJECT_TOKENS` on), `src/init.cpp` (`-corepolicy` neutered on
   mainnet), `src/rpc/rawtransaction_util.cpp` (OP_RETURN `data` builder
   disabled).
6. **Miner template** — `src/node/miner.cpp` excludes non-coinbase OP_RETURN txs
   once active; `TestBlockValidity` runs the full `ContextualCheckBlock`/
   `ConnectBlock` path on the template as the backstop.

## 8. Test plan

- **New functional test** (`test/functional/feature_content_elimination.py`,
  passing): an OP_RETURN meta-protocol marker tx is accepted at H-1 and rejected
  (`bad-txns-opreturn-forbidden`) at H; a non-financial P2MR witness leaf spend
  is rejected (`bad-txns-nonfinancial-witness`) at H; the `data` OP_RETURN RPC
  and default OP_RETURN relay are rejected; and — the **end-to-end PQ**
  demonstration — a normal ML-DSA P2MR payment still confirms and the coinbase
  (witness commitment) stays valid above H.
- **New C++ unit test** (`src/test/content_elimination_tests.cpp`, passing):
  coinbase scriptSig > 40 B rejected (`bad-cb-scriptsig-content`) and an extra
  coinbase OP_RETURN rejected (`bad-cb-opreturn`) — the coinbase cases the
  Python framework cannot mine under MatMul PoW — plus a baseline valid block.
- **PQ preservation** is guaranteed by construction for Pillars 2 & 3: the
  consensus check is the *identical* `IsWitnessStandard` classifier relay
  already applies, so any PQ financial leaf (ML-DSA/SLH-DSA single-sig,
  multisig, CLTV/CSV/CTV covenant, CSFS/HTLC) that relays today also passes
  consensus post-H. The existing `feature_pq_multisig.py`,
  `feature_p2mr_end_to_end.py`, and `feature_pqc_*` suites exercise those leaf
  types.
- **Extend existing**: `mempool_datacarrier.py`, `feature_p2mr_end_to_end.py`,
  `feature_pq_multisig.py`, `wallet_htlc_atomicswap.py`,
  `shielded_v2_wire_tests.cpp`, `script_htlc_templates_tests.cpp`,
  `transaction_tests.cpp`, `script_tests.cpp`.
- **Regression guard**: a corpus test that replays a sample of real mainnet
  P2MR/HTLC/CTV/CSFS/multisig/shielded txs through the post-H validators and
  asserts none regress (the financial-surface guardrail, §6).
- **UTXO survey harness** (§2 caution / §9): scan the UTXO set for P2MR
  commitments whose only known witness would be a non-allowlisted leaf, to size
  any grandfather exemption before fixing H.

## 9. Open items to resolve at sign-off

1. **Activation height H.** Must be a future flag-day, ≥ current tip with ample
   upgrade lead time, and ≥ 125000 (so the shielded-credit disable already
   holds). Provisionally `BTX_CONTENT_ELIMINATION_HEIGHT = 165000`; confirm and
   align to a release train like the existing 61000/123000/125000/128000
   cluster.
2. **Pillar 2 grandfathering.** Run the UTXO survey (§8); if any legitimate
   custody UTXO commits to a currently-non-allowlisted-but-benign leaf, add a
   hash-keyed exemption or widen the allowlist before H.
3. **Pillar 3 CSFS bound.** Confirm with CSFS/delegation/oracle product owners
   the real message shapes (hash-only vs bounded variable) before fixing the
   length rule.
4. **Coordination.** Flag-day fork needs miner/pool + exchange + wallet upgrade
   coordination; publish the height and rationale, and the honest limits (§0.1)
   — pre-H artifacts persist; third-party explorers may still show them.
5. **Naming.** Confirm final symbol names (`nContentEliminationHeight`,
   `IsContentEliminationActive`, reject codes) against house style before code.

## 10. Summary

BTX's genesis-active P2MR-only + 34-byte + 83-byte-OP_RETURN consensus filter
already kills the classic high-bandwidth inscription vectors (taproot envelopes,
bare-multisig/OLGA stamping). The live "artifact" exploits the one lane left
open **by design** — a ≤83-byte OP_RETURN commitment anchoring off-chain
content — and everything "NFT" about it lives in application-layer wallets and
explorers, not the chain. The plan removes that lane and the three remaining latent
transparent channels (P2MR leaf pushes, CSFS/HTLC messages, coinbase scriptSig)
with **structure-based, flag-day-gated** consensus rules that whitelist every
financial operand, plus immediate relay hardening and removal of first-party
meta-protocol tooling. The shielded channel (D) is left to the existing 125000
sunset — it is outflow-only and drains to zero, so a dedicated pillar was
considered and rejected as unjustified consensus surface on a retiring subsystem
(§4). The result: no cheap, uniform, recoverable on-chain channel for any
content/token/NFT meta-protocol to stand on, while all monetary, custody, vault,
swap, bridge, and shielded-exit functionality is preserved byte-for-byte — and
because Pillars 2 & 3 reuse the existing PQ-aware witness classifier verbatim,
the full post-quantum surface (ML-DSA/SLH-DSA signatures, PQ multisig, covenant,
CSFS/HTLC leaves) verifies end-to-end after the fork exactly as before it. The
irreducible residue — a few steganographic bits in programs/amounts — is
economically useless as a protocol substrate and is documented as out of scope
rather than falsely claimed eliminated.
