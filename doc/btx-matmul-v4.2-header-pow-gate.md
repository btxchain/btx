> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul v4 — Header-PoW Spam Gate (audit F1)

*Design + staged mechanism for the forgeable-header-work DoS found in the
wave-2 adversarial audit. Status: gate LOGIC + consensus params + enforcement
point implemented and unit-tested, DISABLED by default
(`nMatMulHeaderPoWDiscountBits == UINT32_MAX`). Wire `nNonce` is compile-time
opt-in (`BTX_ENABLE_HEADER_NONCE_ON_WIRE`, production default OFF) — see §5.
Written 2026-07-16; opt-in plumbing updated 2026-07-19.*

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

## 2. The mitigation: a header-work THROTTLE bound to nBits (audit C2), and why it is not full authentication (audit C1)

Impose an **additional** header validity rule at activated heights whose cost is
**proportional to the chainwork the header claims**:

```
H( GetHash() || spam_nonce )  ≤  ( block_target(nBits) << nMatMulHeaderPoWDiscountBits )
```

Binding the throttle target to the block's OWN difficulty target (`nBits`),
rather than a fixed target, is the audit-C2 correction: forging a header that
claims difficulty `D` now costs `~D / 2^discount` header hashes, so an attacker
cannot pay one easy grind while claiming arbitrarily large ASERT-derived work.
Smaller `discount` = stronger throttle; honest overhead stays negligible because
`SHA256d` is vastly cheaper than a matmul evaluation.

**This is a rate-limiting THROTTLE, not authentication of chainwork (audit C1,
OPEN).** A SHA-based header PoW cannot *authenticate* matmul-calibrated
chainwork: a matmul evaluation is ~10^7× more expensive than a `SHA256d`, so an
attacker can still out-hash the honest matmul work-rate in cheap SHA and forge a
higher-claimed-work header chain — the throttle only bounds the *rate* at which
they can do so (proportional to claimed work), it does not make forging as
expensive as honest mining. **Closing C1 requires one of:**

1. a compact header-verifiable proof of *matmul* work quantitatively bound to the
   chainwork credited from `nBits` (so header acceptance costs real matmul work); or
2. a chain-selection redesign that does **not** credit MatMul chainwork to
   `nChainWork` / best-header / IBD decisions until the block *body* has been
   verified (treat un-authenticated matmul headers as provisional / zero-trusted
   work until the sketch proof validates).

Option 2 is likely the smaller change and avoids a new header-format proof; it is
the recommended direction. Both are **architectural** and out of scope for a
single staged commit — this throttle is the interim, honestly-labelled mitigation.

- `GetHash()` already commits every consensus header field (including the
  self-declared `matmul_digest`), so the gate binds the whole header.
- `H` is `SHA256d` over a fixed little-endian preimage — bit-exact, deterministic.
- The gate target is `nBits`-relative (not a fixed target): it is the block's own
  `DeriveTarget(nBits)` eased by `nMatMulHeaderPoWDiscountBits` (0..255). Honest
  miners satisfy it in a handful of cheap hashes, while flooding `N` fake headers
  claiming difficulty `D` costs `~N·D/2^discount` hashes — proportional to the
  claimed chainwork (audit C2). The discount is the tunable spam price.

**Update (second external audit, 2026-07-16) — H2 discount range + H4 pure
derivation.** The throttle discount (`nMatMulHeaderPoWDiscountBits`, the left
shift on `block_target(nBits)` above) is valid **only in `0..255`**, with
`UINT32_MAX` reserved as the **disabled** sentinel. Values `256..UINT32_MAX-1`
are **rejected fatally at chain-parameter construction** (and fail **closed** —
hardest target — at runtime, never `powLimit`): a discount ≥ 256 would shift the
256-bit target to or past `powLimit`, collapsing the nBits-proportional throttle
back into a **fixed-cost gate** — exactly the constant-work weakness the audit-C2
rebinding removed. Enforced by `Consensus::Params::MATMUL_HEADER_POW_MAX_DISCOUNT_BITS
= 255` + `IsMatMulHeaderPoWDiscountValid()`. The nBits→gate-target mapping is now a
**pure helper `DeriveMatMulHeaderPoWGateTarget(nBits, discount, powLimit)`**
(declared in `pow.h`), which is the tested derivation (H4): fixed-vector tests
(`MatMulHeaderPoWGateTarget_pure_fixed_vectors`) cover discounts 0/1/8/255, the
rejected 256 and `UINT32_MAX-1`, the disabled sentinel, `powLimit` saturation,
and nBits-ordering — vectors a fixed-target implementation cannot reproduce
(the earlier target-binding test was probabilistic because `nBits` sits inside
`GetHash()`).

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

- `Consensus::Params::nMatMulHeaderPoWDiscountBits` (`src/consensus/params.h`):
  the nBits-relative easing (audit C2), **`UINT32_MAX` = disabled sentinel**
  (default). `IsMatMulHeaderPoWEnabled()` is `discount != UINT32_MAX`. The **only**
  valid enabled range is **0..255** (`MATMUL_HEADER_POW_MAX_DISCOUNT_BITS`, audit
  H2); `IsMatMulHeaderPoWDiscountValid()` enforces it. A value in
  `[256, UINT32_MAX-1]` is rejected fatally at chain-parameter construction (it
  would drive the target to `powLimit` irrespective of nBits, recreating the
  fixed-cost C2 gate). There is deliberately NO `nMatMulHeaderPoWHeight`.
- `DeriveMatMulHeaderPoWGateTarget(nBits, discount, powLimit)` (`src/pow.cpp`,
  audit H4): the PURE, directly-testable target derivation (no header, no hash) —
  `DeriveTarget(nBits)` shifted easier by `discount`, saturating at `powLimit`;
  returns `nullopt` for the disabled sentinel, an out-of-range discount, or an
  undecodable nBits.
- `CheckMatMulHeaderSpamGate(header, params)` (`src/pow.cpp`): returns `true`
  immediately when disabled; otherwise computes the gate target via the pure helper
  (fail-**closed** on an out-of-range discount) and compares
  `SHA256d(GetHash() || nNonce) <= gate_target`.
- Enforcement wired into `ContextualCheckBlockHeader` (`src/validation.cpp`),
  gated on `IsMatMulV4Active(nHeight) && IsMatMulHeaderPoWEnabled()`, NOT gated by
  `fSkipMatMulValidation` (a one-hash relay/DoS defense, not an expensive-verify
  correctness check). Reject code `bad-matmul-header-pow`.
- Unit tests (`src/test/pow_tests.cpp`):
  `MatMulHeaderPoWSpamGate_grindable_decoupled_and_enforced` proves the disabled
  sentinel passes, the gate is grindable via `nNonce`, grinding `nNonce` does not
  change `GetHash()` (decoupling), and the target is bound to nBits; and
  `MatMulHeaderPoWGateTarget_pure_fixed_vectors` (H4) pins the exact target for
  discounts 0/1/8/255, the invalid 256 and `UINT32_MAX-1`, the disabled sentinel,
  and the `powLimit` saturation edge.

## 5. The one activation-blocking step: wire-serialize the grinding nonce

`nNonce` is **not** in the default P2P header wire serialization
(`CBlockHeader::SERIALIZE_METHODS` when `BTX_HEADER_NONCE_ON_WIRE == false`), so a
received header always deserializes `nNonce = 0` — the miner's grind is lost in
transit, and the gate cannot be satisfied by relayed headers.

**Production default stays OFF** (`BTX_HEADER_NONCE_ON_WIRE = false`, cmake
`BTX_ENABLE_HEADER_NONCE_ON_WIRE=OFF`) so public wire format remains the 182-byte
identity header. Opt-in for regtest / burn-in:

```
cmake -DBTX_ENABLE_HEADER_NONCE_ON_WIRE=ON ...
```

That flips the compile-time flag, adds `nNonce` to wire serialization (186-byte
wire header), and allows `nMatMulHeaderPoWDiscountBits ∈ [0,255]` past the
startup assert. `GetHash()` **never** includes `nNonce` (identity stays 182 bytes
whether the flag is on or off). Concretely:

1. `CBlockHeader::GetHash()` hashes only the identity field set (182 bytes).
   Wire serialization additionally includes `nNonce` when
   `BTX_HEADER_NONCE_ON_WIRE` (→ 186-byte wire). Block identity = `GetHash()` is
   unchanged; `nNonce` rides along like the payload does for the body (not part
   of the block's identity, so stripping/mutating it in transit just fails the
   gate on that copy — a `BLOCK_MUTATED`-class outcome, not header poisoning).
   Unit tests exercise the future wire via `SerializeWithNonce` /
   `UnserializeWithNonce` without flipping the production default.
2. Set `nMatMulHeaderPoWDiscountBits` in `0..255` from a spam-price calibration
   (target the honest cost at a few ms and the flood price at seconds/header on
   commodity CPUs). Setting it away from the `UINT32_MAX` disabled sentinel is what
   enables the gate — it activates at the SAME flag-day height as the rest of the
   upgrade (no separate gate). Public mainnet/testnet keep `UINT32_MAX` until a
   coordinated activation release that also ships `BTX_ENABLE_HEADER_NONCE_ON_WIRE=ON`.
3. Teach the miner/solver to grind `nNonce` for the gate after sealing the matmul
   winner (`GrindMatMulHeaderSpamNonce` — a few cheap hashes; independent of the
   matmul). Wired from `GenerateBlock` / `MineHeaderForConsensus`.
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
