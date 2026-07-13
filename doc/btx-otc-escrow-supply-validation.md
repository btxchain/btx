# BTX OTC Escrow & Verifiable-Supply Design

**Status:** Design (rev 1) + Phase-1 reference tooling implemented in
[`contrib/otc/`](../contrib/otc/README.md) (offer creation, verification,
watching, bond refund, HTLC settlement wrappers; exercised end to end by
`test/functional/wallet_otc_offer.py`). No consensus changes required —
every construction in this document is expressible with
script/descriptor/RPC surfaces that are already consensus-active and
shipped on `main`.

**Problem being solved:** OTC desks and brokers are quoting large blocks of
BTX for sale that they cannot actually deliver ("phantom supply"), which
suppresses the market price. Today a buyer or the market at large has no way
to distinguish a real 50,000 BTX offer from a screenshot. This document
specifies (a) a trustless-as-possible on-chain escrow for OTC settlement and
(b) a *proof-of-offered-supply* convention that makes phantom offers
mechanically detectable — an offer that does not carry a valid supply proof
is, by market convention, treated as fake.

---

## 1. Threat model: how fake supply works today

| # | Vector | Description |
|---|--------|-------------|
| T1 | **Pure fabrication** | Desk quotes size it never had. "Proof" is a screenshot, a self-reported balance, or nothing. |
| T2 | **Double-pledging** | One real UTXO is shown to many counterparties / venues simultaneously, multiplying apparent supply. |
| T3 | **Borrowed / flash inventory** | Coins are borrowed, shown for the proof, and returned. Supply exists at proof time but is not deliverable. |
| T4 | **Pull-before-settle** | Real coins are shown, but the seller retains a unilateral spend path and withdraws them mid-negotiation while the quote stays live. |
| T5 | **Unconfirmed / reorg-able deposits** | "Supply" is an unconfirmed tx or a low-confirmation output that can be reorged or RBF'd away. |
| T6 | **Unverifiable shielded claims** | "The coins are in the shielded pool." Per-account shielded balances are cryptographically unprovable to third parties on BTX (see §6.3), so such claims are unfalsifiable — perfect cover for T1. |
| T7 | **Settlement default** | Supply is real, but the seller takes the buyer's payment leg and never delivers (or vice versa). Not a supply problem, but the escrow must close it or the supply proof is moot. |

Design goal: **T1–T6 must be detectable by any verifier running a BTX full
node, with no trust in the seller, the venue, or any third party. T7 must be
eliminated for crypto↔crypto trades (atomic) and reduced to a
bounded, non-custodial arbiter for fiat legs.**

## 2. Design principles

1. **No consensus changes.** Everything uses shipped, genesis-active
   features: P2MR MAST trees, ML-DSA-44 / SLH-DSA PQ signatures,
   CLTV/CSV timelocks, CTV (`OP_CHECKTEMPLATEVERIFY`), CSFS
   (`OP_CHECKSIGFROMSTACK`), PQ k-of-n via `OP_CHECKSIGADD_*`, HTLC
   leaves, and the existing descriptor/PSBT/RPC tooling.
2. **Supply proof = confirmed, exclusively-bound, time-locked UTXOs.**
   Not signatures over balances, not attestations — actual coins in the
   UTXO set, spendable only along paths the verifier can enumerate.
3. **Trustless where physics allows.** Crypto↔crypto legs settle
   atomically (HTLC). Fiat legs use an arbiter whose power is *bounded by
   covenant*: the arbiter can pick between two pre-committed outcomes but
   can never redirect funds to itself.
4. **Everything a verifier needs is public.** An offer is a
   self-contained bundle (descriptor + outpoints + terms hash) checkable
   against any full node with `deriveaddresses` + `gettxout` /
   `scantxoutset`. No RPC access to the seller required.

## 3. What BTX already provides (capability inventory)

The chain is unusually well equipped for this. Verified against current
`main`:

- **P2MR MAST** (witness v2, 32-byte Merkle root, `btx1z...`): arbitrary
  multi-leaf script trees; the spend reveals only the taken leaf.
  Reduced-data rules make P2MR the *only* standard output type
  (34-byte scriptPubKey cap, `fEnforceP2MROnlyOutputs`,
  `src/validation.cpp` `CheckReducedDataOutputLimits`), so escrow scripts
  are always committed as Merkle roots — cheap and private.
- **Timelocks:** `OP_CHECKLOCKTIMEVERIFY` / `OP_CHECKSEQUENCEVERIFY`
  (`src/script/interpreter.cpp:559,598`).
- **Covenants:** `OP_CHECKTEMPLATEVERIFY` (BIP-119-style, P2MR leaves,
  `src/script/ctv.{h,cpp}`) — spends can be constrained to an exact
  pre-committed output set.
- **Oracle signatures:** `OP_CHECKSIGFROMSTACK` over
  `TaggedHash("CSFS/btx")` with ML-DSA or SLH-DSA keys
  (`src/script/interpreter.cpp:1286`).
- **PQ k-of-n multisig:** `OP_CHECKSIGADD_MLDSA/_SLHDSA` accumulator
  leaves, ≤ 8 ML-DSA keys per leaf (policy `MAX_PQ_PUBKEYS_PER_MULTISIG`),
  or ~hundreds of 32-byte SLH-DSA keys.
- **First-class escrow descriptors** (`src/script/descriptor.cpp`,
  builders in `src/script/pqm.cpp`):
  - `mr(multi_pq(m,k1,...))`, `sortedmulti_pq`
  - `mr(cltv_multi_pq(locktime,m,k1,...))`, `csv_multi_pq(seq,...)`
  - `mr(ctv_multi_pq(ctv_hash,m,k1,...))`, `ctv(hash)`, CTV+CHECKSIG
  - `htlc(<hash160>,<claimer_key>)` and `refund(<locktime>,<sender_key>)`
    leaves, CSFS delegation leaves
  - Trees: `mr(<primary_leaf>, {<leaf>, <leaf>})` — **the primary slot
    accepts any leaf type** (same `parse_leaf_expr`), so a vault can be
    built with *no* unconditional key path.
- **Escrow spend RPCs:** `buildhtlcclaim` / `buildhtlcrefund`
  (`src/wallet/shielded_rpc.cpp`), exercised end-to-end in
  `test/functional/wallet_htlc_atomicswap.py`.
- **Multi-party signing:** PSBT with dedicated P2MR fields
  (`PSBT_IN_P2MR_LEAF_SCRIPT`, `PSBT_IN_P2MR_PQ_SIG`, CSFS msg/sig
  fields), `createmultisig` (PQ-only), `addpqmultisigaddress`,
  descriptor wallets, offline signing.
- **Supply auditing substrate:** `gettxoutsetinfo` + coinstats index,
  `scantxoutset` (descriptor scan of the UTXO set without wallet import),
  `getshieldedstateinfo.pool_balance` (consensus turnstile = total value
  inside the shielded pool, `src/shielded/turnstile.h`), PQ
  `signmessage` for proof of key control.
- **Cross-chain leg:** wBTX Model B trustless atomic swap
  (`contrib/wbtx/evm/WBTXAtomicSwapHTLC.sol`) shares the exact
  `RIPEMD160(SHA256(preimage))` hashlock with the BTX `htlc()` leaf.

What does **not** exist (and this design routes around): DLC/adaptor
signatures/PTLC (PQ adaptor signatures for ML-DSA are research-grade), any
per-account shielded balance proof, and any proof-of-reserves RPC.

## 4. Core construct: the Bonded Offer Vault (BOV)

The unit of verifiable supply is a **bonded offer**: coins locked in a
P2MR vault whose spend paths are exactly *{settle this offer}* or
*{refund to seller after the offer expires}* — nothing else. The offer is
fake-proof because the coins provably exist, provably cannot be pulled
early (T4), cannot back a second offer (T2), and cannot be "returned to the
lender" before expiry (T3).

### 4.1 Two stages

OTC offers are usually published before a specific buyer exists, so
bonding happens in two stages:

**Stage 1 — Offer bond (no buyer yet).**

```
BOND = mr( multi_pq(2, S_settle, V),          # settlement handoff: seller + venue co-sign
           refund(H_expiry, S_refund) )        # seller-only exit after offer expiry
```

- `S_settle`, `S_refund`: seller ML-DSA keys. `V`: the venue/orderbook
  operator's key (or a 2-of-3 of neutral co-signers for venue-less OTC).
- Before `H_expiry`, coins can move **only** with the venue co-signing,
  and the venue's published policy is to co-sign only a spend whose
  outputs are a Stage-2 trade escrow for *this* offer (venue software
  enforces this mechanically; see §4.4 for the covenant-hardened
  variant). The venue never gains custody — it holds 1 of 2 keys and can
  at worst grief (refuse to co-sign), in which case the seller recovers
  everything at `H_expiry` via the `refund` leaf.
- After `H_expiry` the seller exits unilaterally. A live offer therefore
  always points at an unspent, timelocked UTXO.

For self-published offers with no venue at all, a weaker
**soft bond** is acceptable: `mr(S_settle, {refund(H_expiry, S_cold)})`.
The seller *can* pull early (T4 partially returns), but the pull is
instantly visible — verifiers treat "outpoint spent, offer still quoted"
as proof of bad faith. Markets should prefer hard bonds for size.

**Stage 2 — Trade escrow (buyer engaged).** The bond UTXO is spent
(seller + venue) directly into one of the settlement vaults of §5,
committing to the specific buyer and terms. One transaction; the coins
are never in anyone's unilateral custody in between.

### 4.2 Offer binding: one UTXO, one offer (kills T2)

Every offer has a canonical **terms hash**:

```
offer_terms_hash = SHA256(canonical_json{
    version, seller_id_pubkey, amount_sats, price_or_pricing_formula,
    settle_asset, settle_venue, H_expiry, bond_outpoints[],
    settlement_type, arbiter/oracle keys if any, nonce })
```

The funding transaction that creates the bond UTXO(s) includes one
`OP_RETURN` output:

```
OP_RETURN "BTXOTC1" || offer_terms_hash        # 7 + 32 = 39 bytes ≤ 83-byte cap
```

Because an outpoint has exactly one funding transaction and that
transaction commits to exactly one terms hash, **the same coins can never
verifiably back two different offers** — a second "offer bundle" citing
the same outpoint with different terms fails verification at every
verifier, on every venue, with no cross-venue coordination needed.
Offers funded without the commitment simply verify as *unbound* (tier
B in §4.5) and should be priced/trusted accordingly.

### 4.3 The offer bundle and the verification algorithm

An offer is published (on a venue, in a Signal chat, anywhere) as a
self-contained JSON bundle:

```json
{
  "version": 1,
  "terms": { ...exact fields hashed above... },
  "bond": {
    "descriptor": "mr(multi_pq(2,<S_settle>,<V>),{refund(812000,<S_refund>)})#checksum",
    "outpoints": [ {"txid": "...", "vout": 0} ]
  },
  "attestation": {
    "challenge": "<venue-or-buyer-supplied nonce>",
    "sig": "<PQ signmessage by S_refund over SHA256(terms) || challenge>"
  }
}
```

**Verification (any full node, no seller cooperation):**

1. `getdescriptorinfo` / `deriveaddresses` on the descriptor → address
   `A`. Reject if descriptor grammar or checksum is off.
2. For each outpoint: `gettxout` → exists, unspent, pays to `A`,
   confirmations ≥ `MIN_CONF` (recommend ≥ 20; 90-second blocks make
   this ~30 minutes — see §8.1), sum ≥ `terms.amount_sats`. Kills T1/T5.
3. Fetch each funding tx: `OP_RETURN "BTXOTC1" || H` present and
   `H == SHA256(canonical terms)`. Kills T2.
4. Parse the descriptor tree: the **only** pre-expiry paths are the
   declared settlement path(s), and the refund leaf's locktime
   ≥ `terms.H_expiry`. Kills T3/T4 (no early unilateral exit exists).
5. Verify the PQ attestation signature against `S_refund` and the fresh
   challenge (proves the offer publisher controls the refund key — i.e.
   is the coin owner, not someone replaying a stranger's bond).
6. Continuously: watch the outpoints (`scantxoutset` or a ZMQ watcher).
   Spent-before-settlement ⇒ mark offer dead, flag the seller.

Every step is a handful of standard RPC calls; §9 proposes packaging
steps 1–5 as a single `otc_verifyoffer` RPC / SDK call so wallets and
venues can one-shot it.

### 4.4 Covenant-hardened bond (optional, removes venue trust)

Where the trade's settlement template can be fixed at bond time (known
buyer, fixed split — e.g. a negotiated block trade rather than an open
orderbook offer), replace the venue co-sign with CTV and get a fully
trustless hard bond:

```
BOND = mr( ctv_multi_pq(<H_tmpl>, 1, S_settle),   # seller can ONLY spend into the
           refund(H_expiry, S_refund) )            # pre-committed settlement tx
```

`H_tmpl` is the BIP-119-style template hash of the exact Stage-2 funding
transaction (outputs = the trade escrow of §5 + change). The seller
retains liveness (signs alone) but zero discretion over destination.
This is the strongest form: **no third party, no early exit, no
destination other than the agreed escrow.**

### 4.5 Bond tiers (market convention)

| Tier | Construction | Guarantees | Residual trust |
|------|--------------|-----------|----------------|
| A+ | CTV bond (§4.4) | exists, exclusive, unpullable, destination-fixed | none |
| A | Venue co-sign bond (§4.1) | exists, exclusive, unpullable | venue liveness (griefing only) |
| B | Soft bond + OP_RETURN binding | exists, exclusive, pull is publicly visible | seller restraint pre-settle |
| C | Bare signmessage over arbitrary UTXOs | exists at proof time | everything else (T2/T3/T4) |
| F | Balance screenshots, shielded claims, no proof | none | everything — **treat as no supply** |

Venues and OTC aggregators should display the tier and refuse to list
size above a threshold below tier B. The point of standardizing tiers is
that *price discovery can discount unproven supply to zero*: once real
desks bond at tier A/B, quoting phantom size at tier F stops moving the
market — which is precisely the attack we are defusing.

## 5. Settlement constructions (Stage 2)

### 5.1 Crypto ↔ crypto: HTLC atomic swap — fully trustless (closes T7)

For BTX vs wBTX / stablecoin / any HTLC-capable asset. Already shipped
end to end:

```
SWAP = mr( <internal_or_ctv_leaf>,
           { htlc(<H160>, K_buyer),          # buyer claims with preimage
             refund(H_timeout_btx, S) } )    # seller refunds after timeout
```

- `H160 = RIPEMD160(SHA256(preimage))`, byte-identical to the hashlock in
  `WBTXAtomicSwapHTLC.sol`, so BTX↔EVM swaps work today
  (`contrib/wbtx/btx_wbtx.py`, `buildhtlcclaim` / `buildhtlcrefund`).
- Standard timeout asymmetry: the party that reveals the preimage
  (buyer, claiming the BTX leg) gets the *shorter* window on the other
  chain: `H_timeout_other_leg + Δ < H_timeout_btx`, with `Δ` sized for
  worst-case congestion on both chains (suggest ≥ 24h equivalent).
- Stage-1→Stage-2 flow: the bond spend funds `SWAP` directly; the buyer
  verifies the `SWAP` output in the same tx template before locking
  their own leg.

This is the recommended default for desk-to-desk and desk-to-whale
trades: *no arbiter, no venue, no custody, atomic*.

### 5.2 Fiat leg: bounded-arbiter CTV escrow (arbiter cannot steal)

Fiat cannot be atomic, so we bound the arbiter with covenants instead of
trusting a classic 2-of-3 (where two colluding parties — including the
arbiter — can send funds anywhere):

```
ESCROW = mr( multi_pq(2, K_buyer, S),                      # happy path: both co-sign
             { { ctv_multi_pq(<H_pay_buyer>,   1, K_arb),  # arbiter: release to buyer
                 ctv_multi_pq(<H_refund_seller>,1, K_arb) },# arbiter: return to seller
               refund(H_deadlock, S) } )                    # nuclear fallback
```

- `H_pay_buyer` / `H_refund_seller` are CTV template hashes of the only
  two transactions the arbiter can authorize: *all funds → buyer* or
  *all funds → seller* (templates include fee provisioning; see §8.2).
  **The arbiter chooses an outcome; it can never choose a destination.**
  Collusion with either party yields that party nothing beyond what the
  dispute verdict would — and the arbiter can never pay itself.
- Happy path (fiat arrived, both content) needs no arbiter at all.
- `refund(H_deadlock, S)` with `H_deadlock` well past the dispute window
  guarantees funds never strand if the arbiter vanishes. (Convention:
  buyer must open a dispute — visible to the arbiter — well before
  `H_deadlock`; an arbiter verdict tx confirmed before `H_deadlock`
  settles the matter since the refund leaf is still time-locked.)
- Split verdicts (e.g. 70/30) can be added as additional
  `ctv_multi_pq` leaves for pre-agreed partial-fill templates.

### 5.3 Payment-oracle variant: CSFS "DLC-lite"

Where an automated payment rail can attest fiat arrival (bank API
watcher, PSP webhook, e-money on-chain event), replace the human arbiter
with CSFS oracle leaves:

```
ESCROW = mr( multi_pq(2, K_buyer, S),
             { csfs_pk(K_oracle_offer, K_buyer),    # oracle attestation + buyer sig
               refund(H_timeout, S) } )
```

The oracle signs an attestation message (convention:
`settled:<offer_terms_hash>`, hashed under `TaggedHash("CSFS/btx")`) —
it holds no funds and sees no funds. The buyer claims with the oracle
attestation plus their own signature (`csfs_pk` = CSFS + CHECKSIG,
`BuildP2MRDelegationScript` in `src/script/pqm.cpp:327`).

**Replay caveat (important):** the shipped CSFS leaf is
`<pubkey> OP_CHECKSIGFROMSTACK` — the *message is supplied in the
witness, not pinned by the leaf script*. Any message the oracle key has
ever signed satisfies the leaf. Binding to one trade therefore MUST come
from **per-offer oracle keys**: the oracle derives a fresh key per
`offer_terms_hash` and publishes the mapping; reusing one oracle key
across escrows is unsafe. (A message-pinning leaf variant —
`OP_SHA256 <msg_hash> OP_EQUALVERIFY` before the CSFS check — is
consensus-valid today and is proposed as a Phase-1 descriptor/policy
template addition in §9.)

Oracle equivocation/outage: use k-of-n oracle leaves (n independent
attesters with per-offer keys). Non-attestation degrades to the seller
refund at `H_timeout`, i.e. buyer risk is bounded at "fiat sent, trade
refunded" — which the dispute-window convention (send fiat only well
before `H_timeout − dispute_margin`) plus an arbiter leaf (§5.2 and §5.3
compose in one tree) reduces further.

### 5.4 Classic 2-of-3 (available today, lowest engineering effort)

`mr(multi_pq(2, K_buyer, S, K_arb), {refund(H_deadlock, S)})` via
`createmultisig` / `addpqmultisigaddress` + PSBT. Weaker than §5.2
(arbiter + one party can redirect funds arbitrarily) but deployable this
week with zero new code. Acceptable for small size / trusted arbiters;
venues should label it distinctly from bounded-arbiter escrow.

## 6. Supply validation beyond single offers

### 6.1 Desk-level proof of reserves (standing inventory)

For desks that want to advertise standing inventory (not yet bonded to a
specific offer):

1. Desk publishes a descriptor set (watch-only, e.g. `mr()` ranged
   descriptors) for its inventory addresses.
2. Verifier: `scantxoutset` over the descriptors → total, confirmations.
3. Freshness/control: challenge-response — verifier supplies a nonce,
   desk returns PQ `signmessage` from each address key (or a designated
   proof key per descriptor) over `nonce || height || descriptor_hash`.
4. Anti-T3 (borrowed coins): repeat at random intervals; borrowed
   inventory shows up as churn. For hard guarantees, only bonded offers
   (§4) count — reserves proofs are marketing, bonds are commitments.

This is renBTC/exchange-PoR-grade assurance and intentionally second
class: the tier table (§4.5) prices it as tier C.

### 6.2 Macro supply audit (is the *chain's* supply what it claims?)

Any participant can independently confirm aggregate supply — useful when
"fake supply" FUD is itself the manipulation:

- `gettxoutsetinfo` (coinstats index) → transparent UTXO total +
  UTXO-set hash.
- `getshieldedstateinfo.pool_balance` → consensus turnstile total of
  value inside the shielded pool (`src/shielded/turnstile.h` — the pool
  cannot hold more than this; the invariant is consensus-enforced).
- transparent total + pool balance ≤ emission schedule at height. Any
  discrepancy is a consensus bug, not a market rumor.

### 6.3 Shielded claims: the explicit market rule

BTX has **no mechanism to prove a per-account shielded balance to a third
party** — raw viewing-key export is disabled post-61000
(`z_exportviewingkey` guarded by
`RequireRawViewingKeySharingAllowedOrThrow`), view grants disclose
individual bridge operations, not balances, and no attestation RPC
exists. Moreover the pool is in wind-down: **no new shielded credits
after block 125,000** — only viewing, recovery accounting, and
transparent exits remain, so shielded inventory cannot even be
replenished.

The rule this design asks the market to adopt is therefore simple:
**shielded-balance claims count as zero supply.** A desk with shielded
inventory that wants it counted must exit it transparently (the exit is
the proof) and bond it. This converts T6 from "unfalsifiable claim" into
"non-claim".

## 7. Why this kills phantom supply (economics)

- **Capital lockup is the cost of quoting.** A tier-A/B offer requires
  real coins locked for the offer lifetime. Suppressing price with 10×
  phantom size now requires 10× real capital held out of use — and that
  capital is *visibly committed sell-side*, which is information the
  market prices correctly rather than manipulably.
- **Exclusivity is cryptographic.** T2 (the main force multiplier for
  phantom supply) dies with outpoint-unique OP_RETURN binding: N venues
  showing the same coins collapse to one verifiable offer.
- **Lying is detectable in one RPC round-trip.** Once wallets/venues run
  `otc_verifyoffer` by default, an unproven quote is a self-labeling
  scam. The equilibrium: unproven size trades at zero credibility, so it
  stops being produced.
- **Honest sellers get paid for bonding.** Verifiable firm offers are
  worth a tighter spread (buyer's execution risk on a tier-A offer is
  ~zero), so the convention is adoption-incentivized, not just
  virtue-incentivized.

## 8. Security considerations

1. **Reorgs / PoW maturity (T5).** MatMul PoW is novel; be conservative:
   `MIN_CONF ≥ 20` (~30 min at 90 s spacing) for bond recognition,
   scale with offer size. Verifiers must re-check on reorg (watch
   outpoints, not just one-shot verify).
2. **Fees in CTV templates.** CTV commits to exact outputs; templates
   must embed a fee (recommended: generous, since escrow settlements are
   rare and high-value) or provide a small anchor-style output for CPFP.
   The CTV implementation plan's L2 profile (Appendix E,
   `docs/btx-ctv-csfs-implementation-plan.md`) documents CPFP/package
   relay expectations. Never build a template chain that can strand at a
   fee spike with no bump path.
3. **ML-DSA kill switch.** Consensus carries an emergency
   `nMLDSADisableHeight` (`SCRIPT_VERIFY_DISALLOW_MLDSA`). Long-lived
   escrows should include SLH-DSA backup keys in a parallel leaf
   (mixed-algorithm trees are supported) so funds cannot strand if
   ML-DSA is ever disabled mid-escrow. Recommended for any bond with
   `H_expiry` more than a few weeks out.
4. **Leaf size / standardness.** Relay policy caps leaf scripts at 1,650
   bytes except multisig leaf types (consensus 11,000). One ML-DSA key ≈
   1,315 bytes in-leaf: keep non-multisig leaves to one ML-DSA key (+
   32-byte SLH-DSA or oracle keys), exactly as the shipped `htlc()` /
   `refund()` grammars do; k-of-n ML-DSA committees cap at n ≤ 8.
5. **Oracle/arbiter key hygiene.** Arbiter and oracle keys must be
   per-role, ideally per-offer (the CSFS message binds the terms hash,
   the CTV templates bind destinations, so key reuse is contained — but
   rotation limits blast radius of a key theft).
6. **Privacy.** MAST hides untaken paths: a cooperatively settled trade
   reveals only the 2-of-2 leaf — not the arbiter's existence, the
   dispute templates, or the refund key. The OP_RETURN tag does mark
   bond funding txs as OTC bonds; sellers who dislike that trade
   linkability for tier-B verifiability by choice.
7. **Venue griefing (tier A).** The venue's only power is refusing to
   co-sign, delaying the seller until `H_expiry`. Sellers should size
   `H_expiry` to what they can tolerate having locked, and venues that
   grief are publicly observable (bond refunds at expiry without
   settlement are on-chain).

## 9. Implementation roadmap

**Phase 0 — usable today, zero code.** Tier-B soft bonds + §5.4 2-of-3 +
§5.1 HTLC swaps all work with existing RPCs (`getdescriptorinfo`,
`deriveaddresses`, `importdescriptors`, `createmultisig`, PSBT flows,
`buildhtlcclaim`/`buildhtlcrefund`, `scantxoutset`, PQ `signmessage`).
Publish the offer-bundle JSON schema and the verification checklist
(§4.3) as a market convention document.

**Phase 1 — tooling (contrib/otc + wallet RPCs), no consensus changes.**
The key-management guide already flags canned vault templates as a gap;
fill it with:
- `otc_createoffer` — builds the bond descriptor (tier A/A+/B), funds it
  with the `OP_RETURN "BTXOTC1"||H` commitment, emits the offer bundle.
- `otc_verifyoffer` — runs §4.3 steps 1–5 against the local node;
  returns tier, verified size, expiry, and failure reasons. This is the
  single most important deliverable: verification must be one command.
- `otc_settle` / `otc_refund` — PSBT-based Stage-2 spend builders
  (generalizing `buildhtlcclaim`/`buildhtlcrefund` to the multisig, CTV
  and CSFS leaves), plus `otc_watchoffer` (ZMQ/poll watcher that flags
  spent bonds — same skeleton as the wBTX backing-invariant watcher,
  which is also still unbuilt).
- A `ctv_template` helper RPC to compute BIP-119-style hashes for §4.4 /
  §5.2 templates so integrators never hand-serialize them.
- A message-pinned CSFS leaf (`csfs_msg(<msg_hash>,<oracle_key>,<spender_key>)`
  → `OP_SHA256 <msg_hash> OP_EQUALVERIFY` before the CSFS check):
  consensus-valid today, needs only a descriptor grammar + policy
  template-matcher entry, and removes the per-offer oracle-key
  requirement of §5.3.

**Phase 2 — ecosystem.** Venue integration (display tiers, auto-verify,
shared offer registry keyed by outpoint so double-pledges are flagged
even at tier C), Python SDK in `contrib/otc/` mirroring
`contrib/wbtx/btx_wbtx.py`, and a public verifier web tool backed by
`scantxoutset`.

**Phase 3 — research (optional).** PQ adaptor signatures / PTLC for
scriptless swaps (open research for ML-DSA); zk proof-of-reserves for
any future shielded surface; a standing "offer registry" OP_RETURN
namespace if the market wants offer discovery fully on-chain.

## 10. Worked example (tier A bond → HTLC settlement, regtest-ready)

```bash
# --- Seller creates keys ---
S_SETTLE=$(btx-cli -rpcwallet=desk getnewaddress "" p2mr)
S_SETTLE_PK=$(btx-cli -rpcwallet=desk exportpqkey "$S_SETTLE" | jq -r .pubkey)
S_REFUND=$(btx-cli -rpcwallet=desk getnewaddress "" p2mr)
S_REFUND_PK=$(btx-cli -rpcwallet=desk exportpqkey "$S_REFUND" | jq -r .pubkey)
# Venue publishes V_PK out of band.

# --- Stage 1: bond 50,000 BTX until height 812000 ---
DESC="mr(multi_pq(2,$S_SETTLE_PK,$V_PK),{refund(812000,$S_REFUND_PK)})"
CK=$(btx-cli getdescriptorinfo "$DESC" | jq -r .checksum)
ADDR=$(btx-cli deriveaddresses "$DESC#$CK" | jq -r '.[0]')
# Fund with a tx that also carries: OP_RETURN 4254584f544331 || <terms_hash>
# (send via a raw tx / PSBT with a data output; wallet sendtoaddress + data
#  output helper is a Phase-1 item)

# --- Any buyer verifies (no seller involvement) ---
btx-cli gettxout <txid> <vout>          # unspent, ≥20 conf, pays $ADDR, amount ok
btx-cli getrawtransaction <txid> 2      # OP_RETURN commitment matches terms hash
# descriptor grammar shows: no path before 812000 except 2-of-2 with venue ✔

# --- Stage 2: buyer engages; bond is spent into the swap vault ---
SWAP="mr($S_SETTLE_PK,{htlc($H160,$BUYER_PK),refund(811500,$S_REFUND_PK)})"
# (seller+venue co-sign the bond spend whose sole non-change output is $SWAP_ADDR;
#  buyer locks the wBTX/stable leg under the same H160 with a shorter timeout)

# --- Settlement ---
btx-cli -rpcwallet=buyer buildhtlcclaim "$SWAP#..." '{"txid":"...","vout":0}' \
        "$PREIMAGE_HEX" "$BUYER_DEST" 20000
# or, if the buyer never shows:
btx-cli -rpcwallet=desk buildhtlcrefund "$SWAP#..." '{"txid":"...","vout":0}' \
        "$S_REFUND_DEST" 811500 20000
```

## 11. Summary

| Problem | Answer | Mechanism |
|---------|--------|-----------|
| Does the supply exist? | Provable by anyone | Bond UTXO + confirmations (`gettxout`/`scantxoutset`) |
| Is it double-pledged? | Impossible to hide | `OP_RETURN` terms-hash binding, outpoint uniqueness |
| Can it vanish mid-quote? | No (tier A/A+) | No unilateral pre-expiry path in the MAST tree |
| Is it borrowed for show? | Not while bonded | Timelocked refund leaf ≥ offer expiry |
| Will settlement actually happen? | Atomic for crypto legs | HTLC leaves + `buildhtlcclaim`/`buildhtlcrefund` |
| Fiat-leg disputes? | Bounded arbiter, cannot steal | CTV verdict templates (`ctv_multi_pq`) / CSFS oracles |
| Shielded "trust me" claims? | Counted as zero | No per-account proof exists; pool is sunsetting; exit-then-bond |
| Consensus changes needed? | **None** | All leaves/opcodes/RPCs are live on `main` today |
