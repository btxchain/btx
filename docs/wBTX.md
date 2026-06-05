# wBTX — Canonical Wrapped BTX (specification & integrator note)

**Status: forward-looking specification, announced with the 0.31.0 milestone.** This document defines how
the *canonical* wrapped representation of BTX on EVM chains ("wBTX") will work, so bridges, exchanges, and
DeFi integrators can build against it correctly ahead of its introduction. **It requires no change to BTX
consensus** — BTX stays an 8-decimal, `int64`-satoshi chain. wBTX is an EVM-side token; all decimal handling
lives in the bridge/wrapper contracts.

> Why canonical: BTX will publish a single authoritative wBTX standard (and reference contracts) so the
> ecosystem converges on **one** wrapped representation per chain, rather than fragmenting into competing,
> non-fungible wrappers. Third-party bridges should wrap *this* standard.

## 1. Token parameters
| Field | Value |
|---|---|
| Name / Symbol | Wrapped BTX / **wBTX** |
| Standard | ERC-20 (+ EIP-2612 `permit` recommended) |
| **Decimals** | **18** (EVM-native) |
| Value parity | **1 wBTX := 1 BTX** |
| Supply | Floating; equals BTX locked in bridge custody (1:1 by value) |

## 2. Unit model & the 10^10 scaling factor
- BTX smallest unit: **1 satoshi = 10⁻⁸ BTX** (`COIN = 100,000,000`; `CAmount` is `int64`).
- wBTX smallest unit: **10⁻¹⁸ wBTX** (1 "wei").
- Bridge scale factor: **S = 10¹⁰** ( = 10¹⁸ / 10⁸ ).
  - `wBTX_wei = sats × 10¹⁰`
  - `sats = wBTX_wei ÷ 10¹⁰`
- Consequence: the **lowest 10 decimal digits of a wBTX amount are "sub-satoshi"** — finer than BTX can
  represent. wBTX minted by the bridge is always a multiple of 10¹⁰ (it originated from integer sats); sub-sat
  precision only appears from EVM-side operations (AMM swaps, contract splits, rebasing/yield).

## 3. Mint (BTX → wBTX): lock-and-mint
1. User sends an integer-sat BTX amount to bridge custody on BTX.
2. After confirmations, the bridge mints `sats × 10¹⁰` wBTX to the user's EVM address.
3. Always exact (no rounding) — minted wBTX is a multiple of 10¹⁰.

## 4. Redeem (wBTX → BTX): burn-and-release, **round down**
1. User burns `W` wBTX-wei on the EVM side, targeting a BTX address.
2. Bridge releases `floor(W ÷ 10¹⁰)` satoshis of BTX.
3. The **sub-satoshi remainder `W mod 10¹⁰` is NOT released** — it remains as spendable wBTX (see §5).

**Requirement:** the wrapper/bridge MUST enforce round-down (never attempt to release a fractional sat). The
cleanest implementation is to **only accept redemptions in multiples of 10¹⁰** and let users keep the remainder
as wBTX; an equivalent design accepts any amount and refunds/keeps the `mod 10¹⁰` dust as wBTX.

### Worked example
- Redeem `0.5000000005` wBTX = `500000000500000000` wei.
- `floor(500000000500000000 ÷ 10¹⁰) = 50000000` sats = **0.50000000 BTX released.**
- Dust kept as wBTX: `500000000` wei = `0.0000000005` wBTX (= 5×10⁻¹⁰ wBTX, **< 1 sat**).

## 5. Dust handling (the "can't bridge the last sliver" case)
- The maximum amount ever non-redeemable at once is **< 1 satoshi = < 10⁻⁸ BTX** — economically negligible.
- It is **not lost**: it stays as ordinary wBTX, fully usable/tradeable on EVM. A holder redeems the whole-sat
  portion now and either (a) leaves the dust as wBTX, or (b) **aggregates** dust across holdings/time until it
  reaches ≥ 1 sat, then redeems it.
- Holders do NOT need to "acquire more BTX" to redeem their balance — only the final sub-sat fraction needs
  rounding up if they want to move it across.
- Optional bridge feature: a periodic **dust-sweep** that aggregates rounding remainders.

## 6. Backing & accounting invariants (bridge MUST hold)
- **1:1 backing at the satoshi level:** total redeemable wBTX (in sats, floored) ≤ BTX locked in custody.
- Mint increases locked BTX and wBTX supply by the same sat-value; redeem decreases both by the released sats.
- Track the aggregate sub-sat dust separately; it is backed by custody but only redeemable once aggregated to
  whole sats. Never allow total releasable sats to exceed locked sats.
- wBTX is **only** minted against confirmed locked BTX — no algorithmic/uncollateralized issuance.

## 7. Integrator checklist
- Treat wBTX as **18 decimals**; do not assume sub-sat redeemability — **expect round-down on redeem.**
- For BTX-side amounts, work in integer satoshis (`int64`); convert at the boundary with `×/÷ 10¹⁰`.
- Display/accept BTX with 8 decimals; wBTX with 18.
- Wrap the **canonical** wBTX contract per chain (addresses to be published); do not deploy competing wrappers.
- Honor `MAX_MONEY` (21,000,000 BTX) — wBTX supply can never exceed it in value.

## 8. Trust & security model
- The bridge is a **custodial lock-and-mint** system; its custody/operator/verifier design is the trust point
  (out of scope here). BTX consensus is unchanged and unaware of wBTX.
- Canonical contracts should be audited, upgrade-guarded, and pause-capable; publish addresses through an
  authoritative BTX channel so integrators can verify they are wrapping the real thing.

## 9. Status / roadmap
- **0.31.0:** this specification is published (ecosystem-prep). No on-chain change.
- **Future:** publication of the canonical wBTX reference contracts + the production bridge. Integrators should
  build to this spec now so they are ready at launch.
