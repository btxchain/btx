# contrib/otc — Bonded OTC offers with verifiable supply

Tooling for the design in
[doc/btx-otc-escrow-supply-validation.md](../../doc/btx-otc-escrow-supply-validation.md):
OTC offers backed by **bonded offer vaults**, so that quoted supply is
provably real, exclusively committed to one offer, and not withdrawable
while the quote is live. An offer that does not carry a valid proof bundle
should be treated by the market as **no supply**.

Everything here drives a stock `btxd` over RPC — there are no consensus,
policy, or node changes. Funds-critical spends go through the node's
audited `buildhtlcclaim` / `buildhtlcrefund` wallet RPCs.

**Status: reference tooling. UNAUDITED.** Same caveat as `contrib/wbtx`:
review before using with meaningful value.

## What problem this solves

OTC desks can suppress price by quoting size they do not have (phantom
supply): fabricated balances, the same coins shown to many venues at once,
borrowed coins shown then returned, or "it's in the shielded pool, trust
me" (per-account shielded balances are deliberately unprovable on BTX, and
the pool stopped accepting new credits at block 125,000). A bonded offer
makes every one of those tricks mechanically detectable with nothing but a
full node.

## The bond

A bond is a P2MR vault built from descriptor leaves that already ship in
the node, holding the offered coins with exactly two kinds of spend path:

| Tier | Descriptor | Pre-expiry spend | Guarantee |
|------|-----------|------------------|-----------|
| A+ | `mr(ctv_multi_pq(<tmpl>,1,S),{refund(H,R)})` | only the pre-committed settlement tx | exists, exclusive, unpullable, destination-fixed |
| A  | `mr(multi_pq(2,S,V),{refund(H,R)})` | seller + venue co-sign | exists, exclusive, unpullable (venue can only delay) |
| B  | `mr(S,{refund(H,R)})` | seller alone | exists, exclusive; an early pull is publicly visible |

`refund(H,R)` returns the coins to the seller only at/after block `H`,
which must be ≥ the offer's advertised `expiry_height`.

**Exclusivity** comes from the funding transaction: it must include

```
OP_RETURN "BTXOTC1" || SHA256(canonical offer terms)     (39-byte payload)
```

An outpoint has one funding tx and that tx commits to one terms hash, so
the same coins can never verifiably back two different offers — on any
venue, with no coordination.

## Quick start (CLI)

```bash
# 1. Seller: write terms.json (ints only — floats are rejected)
cat > terms.json <<'EOF'
{
  "version": 1,
  "amount_sats": 300000000,
  "expiry_height": 815000,
  "price": "spot-0.5%",
  "settle_asset": "wBTX",
  "seller_address": "btx1z...",
  "nonce": "<32 hex chars, fresh per offer>"
}
EOF

# 2. Seller: build the bond descriptor (tier B shown; see SDK for A/A+),
#    fund it, and print the publishable offer bundle
python3 btx_otc.py --cli "btx-cli -rpcwallet=desk" \
    create terms.json \
    "mr(<settle_pk>,{refund(815000,<refund_pk>)})" > bundle.json

# 3. Anyone: verify against their own node (exit 0 = verified)
python3 btx_otc.py --cli "btx-cli" verify bundle.json --min-conf 20

# 4. Anyone: watch the bond until it settles / is pulled / expires
python3 btx_otc.py --cli "btx-cli" watch bundle.json

# 5. Seller, after expiry: reclaim via the refund leaf
python3 btx_otc.py --cli "btx-cli -rpcwallet=desk" \
    refund-bond bundle.json <dest_address> --broadcast
```

`verify` re-checks everything on-chain and trusts nothing in the bundle:

1. terms canonicalize; the descriptor parses and matches a **known tier
   shape exactly** (unknown script trees fail closed — a leaf you can't
   classify could be a hidden exit path);
2. the refund timelock covers the advertised expiry;
3. every outpoint is a live, sufficiently-confirmed UTXO paying the vault
   address, summing to at least `amount_sats` (no duplicates);
4. every funding tx carries the `OP_RETURN` commitment to **these** terms
   (this is what catches double-pledging);
5. the offer has not expired;
6. optionally, a fresh-challenge BIP-322 attestation verifies against the
   seller's declared address.

If the node has no `-txindex`, add a `"blockhash"` hint to each outpoint
in the bundle so step 4 can fetch the funding tx.

## Settlement (stage 2)

When a buyer engages, the bond is spent into a settlement vault. For
crypto↔crypto trades use the HTLC vault (identical shape and hashlock
domain to the wBTX Model-B EVM leg, `contrib/wbtx`):

```python
from btx_otc import (swap_vault_descriptor, new_preimage, swap_hash160_hex,
                     build_swap_claim, build_swap_refund)

secret = new_preimage()
desc = swap_vault_descriptor(internal_pk, swap_hash160_hex(secret),
                             buyer_pk, refund_height, seller_pk)
# buyer claims with the preimage (revealing it for the other chain's leg):
raw = build_swap_claim(rpc_buyer, desc_ck, txid, vout, secret, buyer_dest)
# or the seller refunds after the timeout:
raw = build_swap_refund(rpc_seller, desc_ck, txid, vout, seller_dest, refund_height)
```

For fiat legs, see the bounded-arbiter CTV escrow and CSFS oracle
constructions in the design doc (§5.2–5.4); their descriptors are
node-native today, and turnkey builders here are follow-up work.

## Trust model, honestly stated

- **Tier B**: coins exist and are bound to one offer; the seller *can*
  settle-or-pull early, but a pull kills the offer visibly (the watcher
  flags the spent outpoint). Fine for small size; discount accordingly.
- **Tier A**: the venue co-key removes unilateral pulls; the venue never
  has custody and at worst delays the seller until the refund height.
  Co-signing uses the node's standard PQ-multisig PSBT flow.
- **Tier A+**: no third party at all; the covenant fixes the settlement
  destination at bond time. Needs the settlement template known up front
  (negotiated block trades).
- **Attestation binding is declared, not derived**: the challenge
  signature proves the publisher controls `terms.seller_address`, not
  that this address owns the refund key — the *supply* guarantees come
  from the UTXO/commitment/descriptor checks, which need no attestation.
- **Confirmations**: MatMul PoW is young; default to `--min-conf 20`
  (~30 min at 90 s blocks) and scale with size.
- **Long-lived bonds**: consider SLH-DSA keys (`pk_slh(...)` works in
  every leaf) for bonds whose expiry is far out, per the design doc's
  note on the ML-DSA emergency-disable path.

## Files

- `btx_otc.py` — SDK + CLI (offer terms hashing, bond descriptors,
  create/verify/watch, bond refund, HTLC settlement wrappers). Run
  `python3 btx_otc.py selftest` for the offline unit checks; the full
  lifecycle is exercised by `test/functional/wallet_otc_offer.py`.
