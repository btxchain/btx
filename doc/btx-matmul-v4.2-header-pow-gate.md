# BTX MatMul v4 — Header-PoW Spam Gate (audit F1)

*Design + staged mechanism for the forgeable-header-work DoS found in the
wave-2 adversarial audit. Status: gate LOGIC + consensus params + enforcement
point implemented and unit-tested, DISABLED by default (`nMatMulHeaderPoWHeight
== INT32_MAX`). One activation-blocking step remains (wire-serializing the
grinding nonce) — see §5. Written 2026-07-16.*

## 1. The finding (F1, HIGH — architectural, not a consensus break)

At v4 heights the ONLY header-level proof-of-work check is, in
`CheckMatMulProofOfWork_Phase1` (`src/pow.cpp`):

```
if (UintToArith256(block.matmul_digest) > target) return false;   // the whole check
```

`matmul_digest` is a **self-declared 32-byte header field**, not a hash of the
header. It is only *proven* to correspond to real matmul work when the **full
block** arrives (`CheckMatMulProofOfWork_V4ProductCommitted`, which needs the
sketch payload that is not in the header). So an attacker can:

1. Set `matmul_digest = 0` → `0 ≤ target` always passes Phase1 at **zero** work.
2. Satisfy the rest of a header cheaply: `nBits` must equal `GetNextWorkRequired`
   (ASERT — deterministic from ancestry timestamps the attacker controls), seeds
   must equal the deterministic derivation (a few hashes), timestamps MTP-
   monotone and ≤ now+2h. All free.
3. Drive `nBits` arbitrarily hard by feeding ASERT near-constant timestamps
   (blocks appear "instant" → difficulty ramps up), inflating the header's
   **claimed** `nChainWork` past `MinimumChainWork` at no cost.

Bitcoin's header anti-DoS (`HasValidProofOfWork`, `GetAntiDoSWorkThreshold`,
`MinimumChainWork`, headers pre-sync) all rest on the assumption that **producing
a header with valid PoW is expensive** (the header hash must be ≤ target). Here
that assumption is false, so those mitigations are bypassed: a peer with **no
hashpower** can feed a node a fabricated high-claimed-work header chain that is
accepted as `m_best_header`, poisoning best-header and stalling sync while the
node tries to download the (nonexistent/invalid) blocks.

**It is NOT a consensus break.** The full-block validation
(`CheckMatMulProofOfWork_V4ProductCommitted`) recomputes the digest and rejects
the forgery (`high-hash`), so no chain rewrite or theft — the impact is a
remotely-triggerable, zero-cost **resource/liveness DoS** on header sync. The v3
"pre-hash lottery gate" that provided cheap header-spam resistance was retired at
v4 (`validation.cpp`, "the pre-hash lottery gate is retired at v4"), which is
what re-exposes this surface.

## 2. The fix: a cheap, unforgeable header-work gate

Restore "producing a header costs real work" with an **additional** header
validity rule at activated heights:

```
H( GetHash() || spam_nonce )  ≤  DeriveTarget(nMatMulHeaderPoWBits)
```

- `GetHash()` already commits every consensus header field (including the
  self-declared `matmul_digest`), so the gate binds the whole header.
- `H` is `SHA256d` over a fixed little-endian preimage — bit-exact, deterministic.
- `nMatMulHeaderPoWBits` is an **easy** fixed target: honest miners satisfy it in
  a handful of cheap hashes, while flooding `N` fake headers costs `~N/p_gate`
  hashes (`p_gate` = target/2²⁵⁶). This is the tunable spam price.

## 3. Why the grinding nonce MUST be decoupled from the matmul (the key subtlety)

The naive version — reuse `nNonce64` (the matmul nonce) as the grinder — is
**wrong**: `nNonce64` is in `ComputeMatMulHeaderHash` (the operand-B / digest
preimage), so grinding it recomputes the entire matmul. An honest miner would
then need a nonce satisfying BOTH `matmul_digest ≤ target` (the hard PoW) AND the
gate, multiplying honest mining cost by `1/p_gate` — catastrophic (a `p_gate`
small enough to deter flooding, e.g. `2⁻²⁰`, would make honest mining a million×
harder).

The gate therefore needs a grinding field that affects the header hash but **not**
the matmul preimage, so an honest miner grinds it *after* solving the matmul, for
a few cheap hashes, without touching the matmul. The header already carries
exactly such a field: the legacy **`nNonce`** (`uint32`), which is:

- present in `CBlockHeader` (`src/primitives/block.h`),
- **not** in `ComputeMatMulHeaderHash` (so decoupled from operand/digest work),
- **not** in `GetHash()`'s serialization (so it does not perturb block identity,
  genesis, or any pinned header golden).

`spam_nonce := nNonce`. Honest flow: solve matmul (fixes `GetHash()`), then grind
`nNonce` (cheap) until the gate passes. Attacker: `matmul_digest = 0`, then grind
`nNonce` — same `~1/p_gate` per header. The honest tax is a few hashes; the
attacker's per-header cost is the deterrent. (`mix_hash` is an equally-valid
decoupled field; `nNonce` is chosen as it is already a nonce.)

## 4. What is implemented now (disabled) — SINGLE ACTIVATION, no separate gate

The entire MatMul upgrade activates on ONE flag day, so this gate has **no
activation height of its own** — it rides the v4 fork (`IsMatMulV4Active`) and is
enabled purely by a non-zero target. This avoids proliferating activation gates.

- `Consensus::Params::nMatMulHeaderPoWBits` (`src/consensus/params.h`): the easy
  spam target, **`0` = disabled sentinel** (default), and `IsMatMulHeaderPoWEnabled()`
  (`== bits != 0`). There is deliberately NO `nMatMulHeaderPoWHeight`.
- `CheckMatMulHeaderSpamGate(header, params)` (`src/pow.cpp`): the exact gate
  above, bit-exact SHA256d; returns `true` immediately when `bits == 0`.
- Enforcement wired into `ContextualCheckBlockHeader` (`src/validation.cpp`),
  gated on `IsMatMulV4Active(nHeight) && IsMatMulHeaderPoWEnabled()`, NOT gated by
  `fSkipMatMulValidation` (a one-hash relay/DoS defense, not an expensive-verify
  correctness check). Reject code `bad-matmul-header-pow`.
- Unit test `pow_tests/MatMulHeaderPoWSpamGate_grindable_decoupled_and_enforced`:
  proves the disabled sentinel (bits == 0) passes; that once enabled the gate is
  grindable via `nNonce`; that grinding `nNonce` does not change `GetHash()`
  (decoupling); and that an easy-but-nonzero target still rejects most nonces.

## 5. The one activation-blocking step: wire-serialize the grinding nonce

`nNonce` is **not** in the P2P header wire serialization
(`CBlockHeader::SERIALIZE_METHODS`), so a received header always deserializes
`nNonce = 0` — the miner's grind is lost in transit, and the gate cannot be
satisfied by relayed headers. **Activation requires adding `nNonce` to the header
wire serialization** so peers receive the grinder, WITHOUT adding it to
`GetHash()` (which must stay the 182-byte image to keep block identity, genesis
hashes, and every pinned header golden stable). Concretely:

1. Give `CBlockHeader` a hash-only serialization (the current 182-byte field set)
   used by `GetHash()`, and a separate wire serialization that additionally
   includes `nNonce` (→ 186-byte wire header). Block identity = `GetHash()` is
   unchanged; `nNonce` rides along like the payload does for the body (not part
   of the block's identity, so stripping/mutating it in transit just fails the
   gate on that copy — a `BLOCK_MUTATED`-class outcome, not header poisoning).
2. Set `nMatMulHeaderPoWBits` from a spam-price calibration (target the honest
   cost at a few ms and the flood price at seconds/header on commodity CPUs).
   Setting it non-zero is what enables the gate — it activates at the SAME
   flag-day height as the rest of the upgrade (no separate gate).
3. Teach the miner/solver to grind `nNonce` for the gate after sealing the matmul
   winner (a few cheap hashes; independent of the matmul).
4. Testnet burn-in (header propagation with the new wire field; confirm honest
   miners pass trivially and a synthetic header-flood is rate-limited), then
   supermajority signaling — the same single flag-day as the rest of the upgrade.

This is a header-FORMAT change and so is treated as a staged hard fork, not a
same-session live flip: the logic ships reviewed and tested here; the wire change
+ burn-in + activation is the scoped follow-up.

## 6. Severity / priority

HIGH as a header-sync DoS on any enforcing v4 network; **zero** consensus-break
risk (full-block verify always rejects the forgery). It is latent today because
no network has yet activated v4 on mainnet (mainnet leaves `nMatMulV4Height`
unset), so there is time to land the wire change and burn it in before any v4
mainnet activation. Until then, the standard header-sync anti-DoS
(`MinimumChainWork`, headers pre-sync memory bounds, peer eviction) remains the
interim mitigation, with the caveat in §1 that forgeable claimed-work weakens it.
