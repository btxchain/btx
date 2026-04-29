# BTX Shielded Pool: Implementation Gap Analysis

Status note (2026-03-24): this gap analysis is historical context for the March
2026 shielded-pool overhaul. It is not the current reset-chain launch status
document. Current `main` defaults to shielded ring size `8`, supports
configured rings `8..32` on the same wire surface, and the live
benchmark/readiness baseline is in
`doc/btx-shielded-production-status-2026-03-20.md`.

**Status:** Updated 2026-03-06 — many items from the original 2026-03-04 analysis
have been resolved in the `codex/shielded-pool-overhaul` branch.

**Current implementation status:**

- **Category A (Issues 1-6):** Critical design flaws — **RESOLVED**
  - Issue 1 (spend auth anonymity): Resolved via Option B (nullifier binding in ring signature)
  - Issue 2 (no MatRiCT+ impl): **RESOLVED** — full NTT-based lattice ring signature with rejection sampling, challenge chain, key images
  - Issues 3-6 (balance/range proofs, parameters): Implementations complete with proper verification
- **Category B (Issues 7-11):** ML-DSA transition — addressed via PQ key infrastructure
- **Category C (Issues 12-16):** Wallet integration — **RESOLVED** via `CShieldedWallet` class
- **Category D (Issues 17-26):** Shielded RPC commands — **RESOLVED** (z_sendmany, z_shieldcoinbase, z_getbalance, z_listunspent, z_gettotalbalance, z_mergetoaddress, z_viewtransaction)
- **Category E (Issues 27-30):** P2P network protocol — **RESOLVED** (shielded txs relay as standard CTransaction with shielded_bundle field)
- **Category F (Issues 31-33):** Mining and block template — **RESOLVED** (CreateNewBlock handles shielded txs, auto-shield coinbase on maturity)
- **Category G (Issues 34-37):** Reorg and disconnect safety — **RESOLVED** via CShieldedWallet::UndoBlock and nullifier set management
- **Category H (Issues 38-42):** Test coverage — **SUBSTANTIALLY IMPROVED** (unit tests, fuzz targets, stress tests, KAT vectors, E2E tests)

**Remaining hardening items** (non-blocking, tracked for ongoing improvement):
- External cryptographic audit of MatRiCT+ parameter choices
- Formal verification of rejection sampling bounds
- Long-running testnet soak testing for edge cases

---

## Issue 1: Spend Auth Signature May Break Ring Anonymity

### Severity: **Critical**

### The Problem

Each `CShieldedInput` carries both:
1. A **MatRiCT+ ring signature** (inside `spend_proof`) that hides which of the 16 ring members is the real spender
2. A **`spend_auth_sig`** — an ML-DSA or SLH-DSA signature authorizing the spend

The ring signature provides sender anonymity by proving "one of these 16 commitments is mine" without revealing which one. But the `spend_auth_sig` is a standard PQ signature that **must be verified against a specific public key**. If that public key is directly associated with one of the 16 ring members, anyone can check which ring member the signature corresponds to, and ring anonymity is destroyed.

### What the Code Actually Shows

**In the tracker spec** (`btx-shielded-pool-implementation-tracker.md:795-803`), `CShieldedSpendAuthCheck` stores:
```cpp
class CShieldedSpendAuthCheck {
    uint256 m_sighash;
    PQAlgorithm m_algo;
    std::vector<unsigned char> m_pubkey;    // <-- WHICH public key?
    std::vector<unsigned char> m_signature;
};
```

**In the actual implementation** (`src/shielded/validation.cpp:82-94`), `CShieldedSpendAuthCheck` currently does almost nothing — it checks that the nullifier and signature are non-empty, but **does not actually verify the signature against any key**:
```cpp
std::optional<std::string> CShieldedSpendAuthCheck::operator()() const
{
    if (m_txid.IsNull()) return std::string{"bad-shielded-spend-auth-txid"};
    if (m_spend.nullifier.IsNull()) return std::string{"bad-shielded-spend-auth-nullifier"};
    if (m_spend.spend_auth_sig.empty()) return std::string{"bad-shielded-spend-auth-empty"};
    return std::nullopt;  // Always succeeds if non-empty
}
```

The tracker spec's `CShieldedSpend` struct (`btx-shielded-pool-implementation-tracker.md:578-586`) includes `spend_auth_algo` and `spend_auth_sig` fields, but the actual implemented `CShieldedInput` struct (`src/shielded/bundle.h:69-77`) only has `spend_auth_sig` — no algorithm indicator, no public key reference, and no mechanism to verify the signature without de-anonymizing the sender.

**The spec never defines:**
- What key the `spend_auth_sig` is verified against
- How to verify spend authorization without identifying the real ring member
- Whether the public key in the spend_auth_sig is the note's `recipient_pk_hash` (which would be linkable) or a re-randomized key (which would preserve anonymity)

### How to Resolve It

There are exactly three viable approaches:

#### Option A: Zcash Sapling Model — Re-randomized Spend Auth Key (Recommended)

In Zcash Sapling, each spend authorization key (`ak`) is **re-randomized** per-spend using a random scalar `alpha`:

```
rk = ak + alpha * G    (re-randomized key, published on-chain)
spend_auth_sig = Sign(rsk, sighash)    where rsk = ask + alpha
```

The zero-knowledge proof proves (inside the ZK circuit) that `rk` is a valid re-randomization of the spender's `ak`, without revealing `ak`. The verifier checks the signature against `rk` — which is a fresh, unique key for every spend and cannot be linked to any ring member's stored public key.

**For BTX's lattice setting:**
- The ZK proof (which in BTX's case is the MatRiCT+ ring signature itself) must prove knowledge of the relationship `rk = ak + E` where `E` is a small re-randomization error vector (in the lattice setting, this is module-LWE noise rather than a scalar multiple).
- The `spend_auth_sig` is verified against `rk`, which is included in the transaction.
- The ring signature proves that `rk` is a valid re-randomization of one of the 16 ring members' keys, without revealing which one.

**Concrete changes needed:**
1. Add `std::vector<uint8_t> rk` (re-randomized public key) to `CShieldedInput`
2. Extend the MatRiCT+ ring signature to prove `rk = pk_i + E_i` for the real index `i`
3. Verify `spend_auth_sig` against `rk` (not against any ring member's key)
4. The ring signature already hides which `pk_i` is real — the re-randomization ensures `rk` cannot be correlated with any `pk_i` either

**Difficulty:** High. Requires extending the MatRiCT+ protocol to incorporate a re-randomized key proof. In the lattice setting, re-randomization produces a noisy output (`rk ≈ pk + E`), so the proof must show that `rk - pk` has small norm for one ring member. This is a variant of a Module-LWE proof of proximity, which fits naturally into the existing MatRiCT+ framework (same proof technique, same parameters).

#### Option B: Embed Spend Auth Inside the Ring Signature

Eliminate `spend_auth_sig` as a separate field entirely. Instead, have the MatRiCT+ ring signature itself serve as both the ring signature AND the spend authorization. The ring signature already proves knowledge of the spending key corresponding to one of the ring members — that IS spend authorization.

The Fiat-Shamir transcript would need to commit to the transaction sighash, so that the ring signature is bound to a specific transaction (preventing signature reuse).

**Concrete changes:**
1. Remove `spend_auth_sig` from `CShieldedInput`
2. Add the transaction sighash to the ring signature's message hash (already partially done — `RingSignatureMessageHash` could include the tx hash)
3. The ring signature is the only authorization mechanism

**Difficulty:** Medium. The ring signature already signs a message hash over commitments. Adding the tx sighash to that hash is straightforward. The risk is that MatRiCT+ was designed with the ring signature proving properties about commitments, not about transaction authorization — conflating these might interact poorly with the rejection sampling or the Fiat-Shamir transcript if not done carefully.

**Downside:** No separation between proof-of-ownership (ring sig) and transaction authorization (spend auth). In Zcash, the separation allows you to delegate spend auth to a different device without sharing the full proving key.

#### Option C: Sign With a Nullifier-Derived Key

Since the nullifier `nf = SHA256(spending_key || rho || cm)` is already published on-chain and is unique per spend:

1. Derive a one-time signing key from the spending key and nullifier: `osk = KDF(spending_key, nf)`
2. Publish the corresponding one-time public key `opk` in the transaction
3. The ring signature proves that `opk` was correctly derived from the real ring member's key material (without revealing which one)
4. `spend_auth_sig` is verified against `opk`

**Difficulty:** Medium-High. Similar to Option A but uses nullifier-based derivation instead of random re-randomization.

### Recommendation

**Option A (re-randomized key)** is the cleanest approach — it's proven in Zcash Sapling, it separates spend authorization from ring proof, and it maps naturally to the lattice setting. The implementation effort is significant but contained within the MatRiCT+ proof generation and verification.

**If implementation time is critical,** Option B (embed in ring sig) is simpler but loses the spend-auth delegation property.

### Priority: **Must resolve before any shielded pool code goes to consensus**

---

## Issue 2: MatRiCT+ Has No Reference Implementation

### Severity: **Critical**

### The Problem

MatRiCT+ (IEEE S&P 2022, ePrint 2021/545) is an academic protocol with:
- **No open-source implementation** in any language
- **No reference test vectors** from the authors
- Complex lattice-based rejection sampling that silently breaks soundness if done wrong
- Parameter choices that interact non-obviously with concrete security

### What the Code Actually Shows

The `codex/shielded-pool-overhaul` branch has scaffold code in `src/shielded/ringct/`:

| File | Lines | Status |
|------|-------|--------|
| `ring_signature.cpp` | 167 | **Scaffold only.** `CreateRingSignature` fills responses with random small vectors but does NOT implement the actual MLWE-based ring signature protocol. `VerifyRingSignature` just checks that `ComputeChallenge(responses, ...) == challenge_seed` — which is trivially true because `CreateRingSignature` set `challenge_seed` to exactly that value. No actual cryptographic verification. |
| `balance_proof.cpp` | (exists) | Scaffold — needs lattice commitment arithmetic |
| `range_proof.cpp` | (exists) | Scaffold — needs binary decomposition proofs |
| `matrict.cpp` | 186 | Orchestrates the sub-proofs but relies on scaffold implementations |
| `commitment.cpp` | (exists) | Lattice Pedersen commitment — closest to complete |
| `lattice/ntt.cpp` | (exists) | NTT from Dilithium — reusable, correct |
| `lattice/poly.cpp` | (exists) | Polynomial arithmetic — reusable |
| `lattice/sampling.cpp` | (exists) | Gaussian/uniform sampling — needs audit |

**Critical finding:** The "ring signature verification" in `validation.cpp:69-71` uses **deterministic dummy ring members** derived from `SHA256("BTX_Shielded_RingMember_V1" || i || j || nullifier)` — not actual commitment tree entries. This is a test scaffold, not real validation. The `BuildDeterministicRingMembers()` function (`validation.cpp:22-38`) generates ring members from the nullifier alone, meaning:
1. The "ring" is deterministic and public
2. No commitment tree lookup occurs
3. No decoy selection algorithm runs

### What Must Be Implemented

The full MatRiCT+ protocol requires implementing these mathematical objects:

#### 2.1 Lattice Pedersen Commitment Scheme
```
cm = A · r + v · g    (mod q, in R_q^k)
```
Where `A` is a public matrix, `r` is randomness, `v` is the value, `g` is a generator. The existing `commitment.cpp` appears close to this but needs verification against the paper's exact construction.

#### 2.2 MLWE-Based Ring Signature (the core difficulty)

For ring size `M = 16`, module rank `k = 4`:

1. **Prover (real index π):**
   - For each non-real index `j ≠ π`, sample `z_j ← D_σ^{kN}` (discrete Gaussian)
   - Compute commitment `w_j = A · z_j - c_j · pk_j` where `c_j` is the per-member challenge
   - For real index `π`: compute `z_π = y + c_π · sk_π` where `y` is a masking vector
   - **Rejection sampling:** Accept `z_π` only if `||z_π||_∞ < γ - β` (prevents leaking `sk_π`)
   - Compute key image `KI = H(pk_π) · sk_π` (for linkability / double-spend detection)

2. **Fiat-Shamir:** Challenge `c = H(ring_members, key_images, {w_j}, message)`

3. **Verifier:**
   - Recompute all `w_j = A · z_j - c_j · pk_j`
   - Check `||z_j||_∞ < γ - β` for all `j`
   - Recompute challenge and verify match
   - Verify key image consistency

**The current code does NOT implement steps 1-3.** It samples random small vectors and hashes them into a challenge, but there is no MLWE structure, no per-member challenge derivation, no verification equation, and no rejection sampling linked to the secret key.

#### 2.3 Balance Proof
Prove `sum(input_commitments) - sum(output_commitments) = fee · g` in zero knowledge. This is a proof of knowledge of the blinding factor difference, using the same lattice commitment scheme.

#### 2.4 Range Proof
Binary decomposition: prove each output value `v = sum(b_i · 2^i)` where `b_i ∈ {0,1}`. Each bit gets a lattice commitment, and the proof shows each commitment opens to 0 or 1.

### How to Resolve It

There is no shortcut. The implementation must:

1. **Study the paper carefully** (ePrint 2021/545, specifically Sections 4-6 covering the RingCT construction)
2. **Build test vectors by hand** for small parameters (ring size 2, module rank 1, tiny q) to validate the implementation before scaling up
3. **Implement each sub-protocol independently** with its own test suite:
   - Commitment scheme (easiest, ~1 week)
   - Balance proof (~2 weeks)
   - Range proof (~2 weeks)
   - Ring signature with rejection sampling (~4-6 weeks, this is the hard part)
   - Integration into unified proof (~1-2 weeks)
4. **Get the rejection sampling right:**
   - Must use discrete Gaussian sampling (not uniform) for the masking vector `y`
   - The acceptance probability depends on `σ/||c · sk||` — if `σ` is too small, the distribution of `z` leaks information about `sk`
   - If `σ` is too large, proof sizes grow and the soundness parameter degrades
   - The paper specifies exact parameter relationships; these must be followed precisely
5. **Audit against known attacks:**
   - Timing attacks from rejection sampling loops
   - Key leakage from non-uniform response distributions
   - Soundness breaks from insufficient challenge entropy

### Reference Resources

| Resource | What to Extract |
|----------|----------------|
| jaymine/LACTv2 (GitHub) | LACT+ aggregation design, polynomial packing patterns (GPL — study only, cannot copy code) |
| pqabelian/pqringct (GitHub) | Three-key architecture, ring sig API design (ISC license, Go language) |
| Dilithium reference impl (already in BTX) | NTT, polynomial arithmetic, reduction — directly reusable |
| ePrint 2021/545 | The MatRiCT+ paper itself — authoritative source for all parameters and equations |

### Estimated Timeline

| Phase | Duration | Risk |
|-------|----------|------|
| Commitment scheme + tests | 1-2 weeks | Low |
| Balance proof + tests | 2-3 weeks | Medium |
| Range proof + tests | 2-3 weeks | Medium |
| Ring signature + rejection sampling + tests | 4-8 weeks | **High** |
| Integration + end-to-end tests | 2-3 weeks | Medium |
| Security audit by external lattice cryptographer | 4-8 weeks | **High** (availability) |
| **Total** | **15-27 weeks** | |

### Priority: **Critical path — no shielded pool without this**

---

## Issue 3: Turnstile Sign Convention Inconsistency

### Severity: **High → Resolved in code (spec documents inconsistent)**

### The Problem

The assessment flagged that the `value_balance` sign convention appeared inconsistent between spec documents, potentially inverting the inflation check.

### What the Code Actually Shows

**The implemented code is consistent and correct.** Three sources agree:

1. **`src/shielded/turnstile.h:25-27`** (the authoritative source):
   ```cpp
   // value_balance > 0 means value leaves pool (unshield).
   // value_balance < 0 means value enters pool (shield).
   ```

2. **`src/shielded/turnstile.cpp:12`** — `ApplyValueBalance` subtracts:
   ```cpp
   const CAmount new_balance = m_balance - value_balance;
   ```
   - Shield: `value_balance = -1 BTC` → `new_balance = old + 1` (pool grows) ✓
   - Unshield: `value_balance = +1 BTC` → `new_balance = old - 1` (pool shrinks) ✓

3. **`src/shielded/bundle.h:86`** — consistent comment:
   ```cpp
   // Positive: value leaves shielded pool (unshield). Negative: enters pool (shield).
   ```

4. **`src/validation.cpp:3121`** — ConnectBlock applies correctly:
   ```cpp
   if (!next_pool_balance.ApplyValueBalance(bundle.value_balance)) {
       state.Invalid(..., "shielded-pool-balance-negative");
   }
   ```

5. **`doc/btx-shielded-pool-tdd-spec.md:2165-2167`** — spec agrees:
   ```cpp
   // Positive = value flowing FROM shielded TO transparent (unshield).
   // Negative = value flowing FROM transparent TO shielded (shield).
   ```

6. **`doc/btx-shielded-wallet-rpc-concurrency.md:880-882`** — wallet code agrees:
   ```cpp
   // 4e. Set value_balance = net flow from shielded to transparent
   // Positive value_balance means value flows OUT of the shielded pool.
   bundle.value_balance = total_transparent_out;
   ```

### Where the Concern Originated

The TDD spec's `IsShieldOnly()` function (`btx-shielded-pool-tdd-spec.md:2174-2176`) is **backwards**:
```cpp
bool IsShieldOnly() const {
    return !shielded_inputs.empty() && shielded_outputs.empty() && value_balance > 0;
}
```
A shield-only transaction has `value_balance < 0` (value enters pool), not `> 0`. This is `IsUnshieldOnly()` logic with `IsShieldOnly()` naming. The **implemented** `bundle.cpp:92-97` has the correct logic:
```cpp
bool CShieldedBundle::IsShieldOnly() const {
    return shielded_inputs.empty() &&       // no shielded inputs (pure deposit)
           !shielded_outputs.empty() &&     // has shielded outputs
           value_balance < 0;               // value enters pool (correct)
}
```

### Resolution

**The code is correct. The spec has a naming bug in `IsShieldOnly()`/`IsUnshieldOnly()`.** Fix the TDD spec to match the implemented code. The turnstile itself is correct and will prevent inflation as intended.

### What Remains

- Fix the `IsShieldOnly()` / `IsUnshieldOnly()` swap in `btx-shielded-pool-tdd-spec.md:2174-2183`
- No code changes needed — the implementation is already correct

### Priority: **Low (spec cleanup only, no code bug)**

---

## Issue 4: Binding Signature Is Never Defined

### Severity: **High**

### The Problem

`CShieldedBundle` has a `binding_sig` field (`src/shielded/bundle.h:89`):
```cpp
std::vector<uint8_t> binding_sig;
```

The TDD spec says (`btx-shielded-pool-tdd-spec.md:2170-2172`):
```cpp
/** Binding signature proving the value balance is correct.
 *  This prevents inflation by ensuring sum(inputs) == sum(outputs). */
std::vector<uint8_t> binding_sig;
```

And later (`btx-shielded-pool-tdd-spec.md:3152-3154`):
> Additionally, each shielded transaction includes a `binding_sig` that proves
> `sum(input_values) == sum(output_values) + value_balance`.

But **nowhere** is the following specified:
- What key signs the binding signature?
- What message is signed?
- What algorithm is used?
- How is the key derived?

The `CheckStructure()` method in `src/shielded/bundle.cpp:113-131` doesn't even check `binding_sig` — it's possible to pass validation with an empty binding signature. The test cases in the TDD spec use `binding_sig = {0x01}` — a single placeholder byte.

### Why This Matters

In Zcash Sapling, the binding signature serves a critical role:

1. Each value commitment uses a Pedersen commitment: `cv = v·G + rcv·H`
2. The sum of input `cv`s minus output `cv`s equals `value_balance·G + (sum_rcv)·H`
3. The binding signature is signed with key `bsk = sum(rcv_inputs) - sum(rcv_outputs)` — the aggregated blinding factor
4. Only someone who knows ALL the blinding factors (i.e., the transaction creator) can sign
5. This prevents a third party from modifying `value_balance` without invalidating the binding sig

Without a binding signature, an attacker who can modify the transaction in-flight could change `value_balance` and inflate the supply.

### How to Resolve It

#### In BTX's lattice setting:

The MatRiCT+ balance proof already proves `sum(input_commitments) - sum(output_commitments) = fee·g + value_balance·g`. If this proof is bound to the transaction (via Fiat-Shamir including the tx sighash), it already serves the binding-signature role.

**Two options:**

**Option A: The balance proof IS the binding signature**

If the MatRiCT+ proof's Fiat-Shamir transcript commits to:
- All input commitments
- All output commitments
- The fee
- The `value_balance`
- The transaction sighash

Then the proof itself binds `value_balance` to the transaction. No separate binding signature is needed. Remove the `binding_sig` field and add a comment explaining that the MatRiCT+ proof serves this role.

**This is the recommended approach** because:
- It reduces transaction size
- It avoids defining a new signature scheme
- The balance proof already proves the exact property that binding_sig would prove

**Option B: Lattice-based binding signature**

Derive a binding key from the blinding factor sum (analogous to Zcash):
```
bsk = sum(input_blinds) - sum(output_blinds)    // polynomial vector
bpk = A · bsk                                     // public key
binding_sig = ML-DSA.Sign(bsk, sighash || value_balance)
```

This requires defining a custom signature scheme over the lattice commitment blinding factors. It's more complex and adds ~2.4 KB (ML-DSA signature) to every shielded transaction.

### Recommendation

**Option A.** Ensure the MatRiCT+ Fiat-Shamir transcript commits to `value_balance` and the transaction sighash, then remove `binding_sig` as a separate field. Document explicitly that the balance proof serves as the binding guarantee.

If the team prefers an explicit binding signature for defense-in-depth, Option B works but adds complexity and size.

### Priority: **Must resolve before consensus — either remove the field or define its construction**

---

## Issue 5: CTV Doesn't Commit to Shielded Outputs

### Severity: **High**

### The Problem

The CTV hash computation (`src/script/interpreter.cpp:1682-1699`) commits to:
```
SHA256(version || nLockTime || [scriptsigs_hash] || vin_count ||
       sequences_hash || vout_count || outputs_hash || input_index)
```

Where `outputs_hash = SHA256(serialized transparent outputs)`.

The CTV hash does **NOT** include:
- `shielded_bundle` data (shielded inputs, outputs, proofs)
- `value_balance`
- `binding_sig`

This means a CTV-constrained transaction template binds the transparent outputs but leaves the shielded portion free. An attacker (e.g., a malicious bridge operator) could satisfy a CTV covenant while replacing the intended shielded outputs with different ones.

### The Bridge Scenario

The BTX shielded pool spec describes a bridge architecture (`btx-shielded-pool-tdd-spec.md:1977-2244`) where:

1. User sends transparent BTC to a CTV-constrained P2MR address
2. The CTV hash commits to a specific shield transaction template
3. The bridge operator completes the shield transaction, moving value into the shielded pool

If CTV doesn't bind the shielded outputs, the operator could:
- Satisfy the CTV constraint (matching the transparent outputs)
- Replace the shielded output's note commitment with one they control
- Steal the shielded value

### Why This Is Non-Trivial to Fix

CTV was designed for Bitcoin's transparent UTXO model. Extending it to cover shielded data requires deciding:

1. **What shielded data to commit to?**
   - The full serialized `shielded_bundle`? (brittle — any proof format change breaks all outstanding CTV hashes)
   - Just the note commitments and `value_balance`? (sufficient for binding value flow)
   - The note commitments, `value_balance`, and nullifiers? (most complete)

2. **Backward compatibility:**
   - Changing the CTV hash computation is a consensus change
   - Existing CTV scripts (without shielded data) must continue to work

### How to Resolve It

#### Option A: Extended CTV Hash (Recommended)

Add a new hash variant that includes shielded data when present:

```cpp
uint256 ComputeCTVHashImpl(const T& tx, uint32_t nIn, const PrecomputedTransactionData& txdata)
{
    HashWriter ss{};
    ss << tx.version;
    ss << tx.nLockTime;
    if (txdata.m_ctv_has_scriptsigs) {
        ss << txdata.m_ctv_scriptsigs_hash;
    }
    ss << static_cast<uint32_t>(tx.vin.size());
    ss << txdata.m_sequences_single_hash;
    ss << static_cast<uint32_t>(tx.vout.size());
    ss << txdata.m_outputs_single_hash;
    ss << nIn;

    // NEW: Include shielded bundle commitment when present
    if (tx.HasShieldedBundle()) {
        const auto& bundle = tx.GetShieldedBundle();
        HashWriter shielded_hw{};
        shielded_hw << bundle.value_balance;
        for (const auto& output : bundle.shielded_outputs) {
            shielded_hw << output.note_commitment;
        }
        for (const auto& input : bundle.shielded_inputs) {
            shielded_hw << input.nullifier;
        }
        ss << shielded_hw.GetSHA256();
    }

    return ss.GetSHA256();
}
```

**Concern:** This changes the CTV hash for ALL transactions with shielded bundles. Since BTX is a new chain (not a soft fork of Bitcoin), this is acceptable — there are no existing CTV scripts to break.

**But:** CTV scripts that DON'T involve shielded data should produce the same hash as before. The solution above only appends to the hash when a shielded bundle is present, so non-shielded CTV scripts are unaffected.

#### Option B: New Opcode `OP_CHECKSHIELDEDTEMPLATEVERIFY`

Leave CTV unchanged. Introduce a new opcode that specifically commits to the shielded bundle alongside the transparent template. Bridge scripts would use `CTV + CSTV` (both checks in the same leaf script).

**Advantage:** CTV remains simple and unchanged. The new opcode is purpose-built for shielded bridge flows.

**Disadvantage:** Two opcodes where one suffices. Bridge scripts become more complex.

#### Option C: Use CSFS for shielded binding

The bridge operator could be required to sign the shielded output commitments via CSFS. The CTV binds the transparent outputs, and the CSFS signature binds the shielded outputs.

**Advantage:** No consensus change to CTV. Uses existing CSFS infrastructure.

**Disadvantage:** Requires the bridge operator to sign — doesn't work for trustless shield operations.

### Recommendation

**Option A** for a new chain. Since BTX hasn't launched, the CTV hash should be extended now to include shielded data when present. This is the cleanest long-term solution and avoids the need for additional opcodes or trust assumptions.

### Priority: **Must resolve before launch if CTV-based bridge is a launch feature. Can defer if bridges are post-launch.**

---

## Issue 6: Ring Member Selection Algorithm Is Unspecified

### Severity: **High**

### The Problem

The tracker spec describes ring member (decoy) selection as:
```cpp
struct RingSelector {
    /** Select RING_SIZE - 1 decoy commitments from the tree for each input.
     *  Uses gamma distribution for recency bias (similar to Monero). */
    std::vector<std::vector<uint256>> SelectRings(
        const ShieldedMerkleTree& tree,
        const std::vector<uint64_t>& real_positions,
        size_t ring_size = RING_SIZE);
};
```

But:
- No gamma distribution parameters are specified (shape, scale)
- No `ring_selection.h` or `ring_selection.cpp` file exists in the codebase
- The actual validation code (`src/shielded/validation.cpp:22-38`) uses `BuildDeterministicRingMembers()` — deterministic dummy ring members derived from the nullifier, not actual commitment tree entries

**This matters because a bad decoy selection algorithm completely defeats ring signature privacy.** Monero has had multiple papers demonstrating that suboptimal decoy selection makes the real input statistically identifiable (see "An Empirical Analysis of Traceability in the Monero Blockchain" and related work).

### Key Design Decisions Needed

#### 6.1 Selection Distribution

The selection distribution must match the real spend age distribution. If real spends tend to be recent (within a few blocks) but decoys are selected uniformly across the tree, an observer can identify the real input as the most recent one.

**Monero's approach:** Gamma distribution with parameters fit to observed spend age data. As of Monero v15+, the parameters are approximately `shape = 19.28, scale = 1/1.61` (applied to `log(block_age)`), producing a heavy-tail distribution biased toward recent outputs.

**BTX should:**
1. Define the exact distribution parameters
2. These parameters become consensus-adjacent — if different wallets use different distributions, transactions from each wallet are distinguishable
3. The parameters should be published in a BIP-like spec and enforced by policy (not consensus, since decoy selection is wallet-side)

#### 6.2 Selection Domain

Ring members must be selected from the commitment tree, not from arbitrary data. Each ring member is identified by its **tree position** (index into the incremental Merkle tree).

**Key constraint:** The selected positions must:
- Be valid (have a commitment at that position)
- Not include the real input's position (or include it exactly once)
- Be from a recent enough tree state that the sender can compute Merkle paths for all ring members

#### 6.3 Consensus-Side Ring Validation

The consensus layer must verify that all ring members reference valid tree entries. The current code doesn't do this (it generates dummy ring members). The real implementation needs:

```cpp
// For each spend in the bundle:
//   For each ring_position in spend.ring_positions:
//     Verify ring_position < tree.size() at the anchor height
//     Retrieve the commitment at that position
```

This requires either:
- The ring positions to be included in the transaction (current tracker spec: `std::vector<uint64_t> ring_positions`)
- A deterministic ring selection algorithm that validators can reproduce from the transaction data

**Important:** Ring positions MUST be part of the transaction data, not wallet-side only, because validators need to know which ring members to use for verification.

#### 6.4 Timing Attacks on Ring Position

If ring positions are included in the transaction, observers can analyze position patterns across transactions to de-anonymize senders. The selection algorithm must produce statistically indistinguishable position sets regardless of which position is real.

### How to Resolve It

#### Step 1: Choose distribution parameters

Study the expected BTX shielded transaction patterns (or use Monero's well-researched parameters as a starting point):

```cpp
// src/shielded/ringct/ring_selection.h

struct RingSelectionParams {
    static constexpr double GAMMA_SHAPE = 19.28;
    static constexpr double GAMMA_SCALE = 1.0 / 1.61;
    static constexpr size_t MIN_DECOY_AGE = 10;     // blocks
    static constexpr size_t MAX_DECOY_AGE = 100000;  // blocks
};
```

#### Step 2: Implement the selection algorithm

```cpp
std::vector<uint64_t> SelectDecoys(
    const ShieldedMerkleTree& tree,
    uint64_t real_position,
    uint64_t current_tree_size,
    size_t ring_size,
    FastRandomContext& rng)
{
    std::vector<uint64_t> positions;
    positions.push_back(real_position);

    while (positions.size() < ring_size) {
        // Sample from gamma distribution (applied to log(age))
        double log_age = rng.gamma(GAMMA_SHAPE, GAMMA_SCALE);
        int64_t age = static_cast<int64_t>(std::exp(log_age));
        age = std::clamp(age, MIN_DECOY_AGE, current_tree_size - 1);

        uint64_t position = current_tree_size - 1 - age;
        if (position < current_tree_size &&
            std::find(positions.begin(), positions.end(), position) == positions.end()) {
            positions.push_back(position);
        }
    }

    // Shuffle to hide real position
    std::shuffle(positions.begin(), positions.end(), rng);
    return positions;
}
```

#### Step 3: Add ring positions to the transaction format

The tracker spec already has this in `CShieldedSpend`:
```cpp
std::vector<uint64_t> ring_positions;   // RING_SIZE positions
```

But the implemented `CShieldedInput` (`src/shielded/bundle.h:69-77`) does NOT include ring positions. This field must be added.

#### Step 4: Validation-side ring member lookup

```cpp
// In ConnectBlock / CheckShieldedBundle:
for (const auto& spend : bundle.shielded_inputs) {
    for (uint64_t pos : spend.ring_positions) {
        if (pos >= tree_size_at_anchor) {
            return Invalid("bad-shielded-ring-position");
        }
        ring_member_commitments.push_back(tree.GetCommitmentAt(pos));
    }
}
```

### Priority: **Must implement before shielded pool launch — privacy is meaningless without proper decoy selection**

---

## Summary: Resolution Priority and Dependencies

```
                    ┌──────────────────────────────┐
                    │   Issue 2: MatRiCT+ impl     │
                    │   (15-27 weeks, critical      │
                    │    path for everything)       │
                    └──────────┬───────────────────┘
                               │ depends on
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
   ┌────────────────┐ ┌───────────────┐ ┌────────────────┐
   │ Issue 1:       │ │ Issue 4:      │ │ Issue 6:       │
   │ Spend auth /   │ │ Binding sig   │ │ Ring member    │
   │ ring anonymity │ │ definition    │ │ selection      │
   │ (integrated    │ │ (likely       │ │ (independent   │
   │  into MatRiCT+ │ │  removed if   │ │  but needs     │
   │  proof)        │ │  balance proof│ │  tree lookup)  │
   │                │ │  suffices)    │ │                │
   └────────────────┘ └───────────────┘ └────────────────┘

   ┌────────────────┐ ┌───────────────┐
   │ Issue 3:       │ │ Issue 5:      │
   │ Turnstile sign │ │ CTV shielded  │
   │ (RESOLVED -    │ │ binding       │
   │  spec cleanup) │ │ (independent) │
   └────────────────┘ └───────────────┘
```

| # | Issue | Resolution | Effort | Blocks Launch? |
|---|-------|-----------|--------|----------------|
| 1 | Spend auth breaks ring anonymity | Re-randomized key (Option A) or embed in ring sig (Option B) | Integrated into Issue 2 | **Yes** |
| 2 | MatRiCT+ no reference impl | Full implementation from paper with external audit | 15-27 weeks | **Yes** |
| 3 | Turnstile sign convention | Fix `IsShieldOnly()`/`IsUnshieldOnly()` naming in TDD spec | 5 minutes | No (spec only) |
| 4 | Binding signature undefined | Remove field if MatRiCT+ balance proof commits to tx sighash | 1 day (decision) + 1 week (impl) | **Yes** |
| 5 | CTV doesn't bind shielded outputs | Extend CTV hash to include shielded data when present | 1-2 weeks | Only if CTV bridge is launch feature |
| 6 | Ring member selection unspecified | Define distribution parameters + implement selection + add ring positions to tx format | 2-3 weeks | **Yes** |

---

## Category B: ML-DSA to SLH-DSA Emergency Transition Gaps

These are detailed in `doc/btx-design-assessment.md` Appendix A. The cryptographic infrastructure for SLH-DSA backup is already complete (default wallet descriptor is dual-leaf `mr(<mldsa>,pk_slh(<slhdsa>))`, signing flow is algorithm-agnostic, fee estimation covers SLH-DSA worst case). What is missing is operational tooling for an emergency where ML-DSA is broken and users must mass-migrate to SLH-DSA spending.

### Issue 7: ML-DSA Disable Consensus Mechanism

**Severity: High (must be in genesis consensus rules)**

No mechanism exists to reject ML-DSA signatures network-wide. If ML-DSA is broken, attackers can forge ML-DSA signatures instantly while legitimate users need 50-100ms per UTXO to sign via SLH-DSA. The attacker wins the race.

**What to implement:** A pre-defined consensus activation mechanism (BIP-9 style signaling or emergency flag day height) that after activation treats `OP_CHECKSIG_MLDSA` and `OP_CHECKSIGADD_MLDSA` as always-fail. This must be designed before launch because nodes without the mechanism cannot participate in emergency activation.

**Files to modify:**
- `src/script/interpreter.cpp` — add activation-height check before ML-DSA sig verification
- `src/consensus/params.h` — add `nMLDSADisableHeight` or `vDeployments` entry
- `src/chainparams.cpp` — set activation parameters (initially disabled/far-future)
- `src/versionbits.h/cpp` — if using BIP-9 signaling

### Issue 8: Leaf Selection Control in Signing

**Severity: Medium (before launch)**

`SignP2MR()` in `src/script/sign.cpp` iterates leaves in lexicographic order by script bytes and picks the first leaf where it has key material. No mechanism to request SLH-DSA leaf spending.

**What to implement:** A `coin_control` option or RPC flag (`--use-algo slh`) that pre-selects the SLH-DSA leaf script and control block in `SignatureData` before the signing loop runs.

**Files to modify:**
- `src/wallet/coincontrol.h` — add optional `PQAlgorithm leaf_preference` field
- `src/script/sign.cpp` — check `leaf_preference` in `SignP2MR` before iterating
- `src/wallet/spend.cpp` — pass coin_control leaf preference to signing
- `src/wallet/rpc/spend.cpp` — add `use_algo` parameter to `sendtoaddress`/`sendmany`

### Issue 9: Batch Sweep RPC

**Severity: Medium (before or shortly after launch)**

No RPC exists for walking the wallet UTXO set and constructing batched SLH-DSA-leaf spends.

**What to implement:** An RPC like `sweeptoself` that iterates UTXOs, builds weight-respecting batched transactions spending via the SLH-DSA leaf, and submits them.

**Files to create:**
- `src/wallet/rpc/sweep.cpp` — `sweeptoself` RPC implementation

**Files to modify:**
- `src/wallet/rpc/spend.cpp` — or add to existing spend RPC file
- `src/wallet/CMakeLists.txt` — add new source file

### Issue 10: Emergency Relay Policy

**Severity: Low-Medium (can ship post-launch)**

SLH-DSA transactions are 2.1x larger and 10x more expensive to validate. If everyone sweeps simultaneously, mempool and block production are strained.

**What to implement:** Policy-level SLH-DSA transaction priority boost and/or temporary validation weight discount during an ML-DSA emergency. This is policy-only (not consensus) so can be added post-launch.

**Files to modify:**
- `src/policy/policy.h` — add emergency mode fee/weight adjustments
- `src/validation.cpp` — apply emergency relay policy when ML-DSA disable is active

### Issue 11: Post-Emergency Default Descriptor Switch

**Severity: Low (can ship post-launch)**

After ML-DSA is disabled, new addresses should use `mr(pk_slh(<key>))` instead of the dual-leaf descriptor.

**What to implement:** A wallet config option or automatic activation-height detection that switches the default descriptor template from dual-leaf to SLH-DSA-only.

**Files to modify:**
- `src/wallet/walletutil.cpp` — make default descriptor conditional on ML-DSA disable status
- `src/wallet/wallet.h` — add config flag for descriptor template

---

## Category C: Wallet Integration (Entirely Unbuilt)

The entire shielded wallet subsystem is specified in `doc/btx-shielded-wallet-rpc-concurrency.md` and `doc/btx-shielded-pool-implementation-tracker.md` Section 7, but zero lines of implementation exist.

### Issue 12: CShieldedWallet Core Class

**Severity: Critical (blocks any shielded use)**

No wallet-side shielded functionality exists. The wallet cannot track owned notes, compute shielded balances, or construct shielded transactions.

**What to implement:**

```cpp
class CShieldedWallet {
    RecursiveMutex cs_shielded;
    std::map<Nullifier, ShieldedCoin> m_notes;           // owned notes
    std::set<Nullifier> m_spent_nullifiers;               // spent markers
    std::map<uint256, ShieldedMerkleWitness> m_witnesses; // per-note witnesses
    std::vector<MLKEMKeyPair> m_kem_keys;                 // ML-KEM for decryption
    std::vector<CPQKey> m_spending_keys;                  // spending authorization
    const ShieldedMerkleTree* m_tree;                     // global tree reference

    void ScanBlock(const CBlock& block, int height);
    CAmount GetShieldedBalance() const;
    std::vector<ShieldedCoin> GetSpendableNotes() const;
    std::optional<CMutableTransaction> CreateShieldedSpend(...);
    std::optional<CMutableTransaction> ShieldFunds(...);
    std::optional<CMutableTransaction> UnshieldFunds(...);
};
```

**Files to create:**
- `src/wallet/shielded_wallet.h` (~300 lines)
- `src/wallet/shielded_wallet.cpp` (~800 lines)

**Files to modify:**
- `src/wallet/wallet.h` — add `std::unique_ptr<CShieldedWallet> m_shielded_wallet` member
- `src/wallet/wallet.cpp` — initialize shielded wallet, connect to `CValidationInterface`

### Issue 13: Shielded Coin Selection

**Severity: Critical (blocks shielded spending)**

No coin selection algorithm exists for choosing which shielded notes to spend.

**What to implement:** `ShieldedCoin` struct representing the wallet's view of a note, plus coin selection logic that considers note value, confirmation depth, and effective value after proof-size-based fees.

**Files to create:**
- `src/wallet/shielded_coins.h` (~80 lines)
- `src/wallet/shielded_coins.cpp` (~200 lines)

### Issue 14: ML-KEM Key Derivation

**Severity: Critical (blocks note encryption/decryption)**

No ML-KEM key derivation exists. The three-key model requires spending key (already exists at `m/87h/...`), KEM key (missing, at `m/88h/...`), and view key (derived from KEM key).

**What to implement:** `DeriveMLKEMKeyFromBIP39()` following the same HKDF pattern as `src/wallet/pq_keyderivation.h`.

**Files to modify:**
- `src/wallet/pq_keyderivation.h` — add `DeriveMLKEMKeyFromBIP39()` declaration
- `src/wallet/pq_keyderivation.cpp` — implement ML-KEM key derivation at `m/88h/coin_type'/account'/0/index`

### Issue 15: Block Scanning and Note Detection

**Severity: Critical (blocks receiving shielded funds)**

No `ScanBlock()` implementation exists. The wallet must scan every block for incoming notes by attempting ML-KEM decapsulation on each shielded output, using view tag pre-filtering for a ~256x speedup.

**What to implement:** Per-block scanning that:
1. Checks if any nullifiers match owned notes (detect spends)
2. Tries to decrypt each output with each owned KEM key (detect receives)
3. Updates incremental Merkle witnesses for all unspent notes

This is integrated into `CShieldedWallet::ScanBlock()` (Issue 12).

### Issue 16: Incremental Witness Maintenance

**Severity: Critical (blocks shielded spending)**

After a note is received, its Merkle witness must be updated every time a new note is appended to the commitment tree. The `ShieldedMerkleWitness` class in `src/shielded/merkle_tree.h` supports incremental updates, but no wallet code calls it.

**What to implement:** On every block, for every unspent note the wallet owns, call `witness.IncrementalUpdate()` with each new commitment appended to the tree in that block.

This is integrated into `CShieldedWallet::ScanBlock()` (Issue 12).

---

## Category D: Shielded RPC Commands (Entirely Unbuilt)

None of the shielded RPC commands exist. They are specified in `doc/btx-shielded-pool-implementation-tracker.md` Section 7.6.

### Issue 17: z_getnewaddress

Generate a new shielded address (spending key + KEM key pair). Returns the shielded address string.

### Issue 18: z_getbalance

Query the confirmed and unconfirmed shielded balance across all owned notes.

### Issue 19: z_listunspent

List all spendable shielded notes with value, confirmation height, and nullifier.

### Issue 20: z_sendmany

Core shielded send RPC. Supports shielded-to-shielded and shielded-to-transparent transfers. Must handle note selection, proof generation, change note creation, and fee calculation.

### Issue 21: z_shieldcoinbase

Shield mining rewards (coinbase UTXOs) into shielded notes.

### Issue 22: z_shieldfunds

Shield arbitrary transparent UTXOs into shielded notes.

### Issue 23: z_mergenotes

Consolidate small shielded notes into fewer larger ones (reduces future spending proof counts).

### Issue 24: z_viewtransaction

View details of a shielded transaction if the wallet owns the relevant keys. Decrypts note values, memos, and identifies sender/receiver.

### Issue 25: z_exportviewingkey / z_importviewingkey

Export and import view-only keys for watch-only shielded wallets.

### Issue 26: z_shieldedaddress validation and address format

Define the shielded address encoding format (analogous to Zcash's zs1... addresses). Implement encoding/decoding and `z_validateaddress` support.

**Files to create:**
- `src/wallet/shielded_rpc.cpp` (~600 lines total for all RPCs)

**Files to modify:**
- `src/wallet/rpc/spend.cpp` — register z_* RPC commands
- `src/rpc/client.cpp` — register z_* parameter names

---

## Category E: P2P Network Protocol (Entirely Unbuilt)

No shielded-specific P2P protocol exists. Specified in `doc/btx-shielded-pool-implementation-tracker.md` Section 8.

### Issue 27: NODE_SHIELDED Service Flag

Nodes must advertise shielded transaction support. Shielded txns should only be relayed to peers with this flag.

**Files to modify:**
- `src/protocol.h` — add `NODE_SHIELDED = (1 << 8)` to `ServiceFlags`
- `src/protocol.cpp` — register message type strings

### Issue 28: Shielded Transaction Relay

Shielded transactions are 7-10x larger than typical transparent transactions (~25-35 KB each). Relay must:
1. Validate proofs before forwarding (prevent DoS via invalid proofs)
2. Apply bandwidth rate limiting per peer (~500 KB/s for shielded relay)
3. Only relay to `NODE_SHIELDED` peers

**Files to modify:**
- `src/net_processing.h` — add shielded relay tracking state
- `src/net_processing.cpp` — handle shielded tx relay, validation before forwarding, rate limiting

### Issue 29: Shielded Data Messages

New message types for requesting and serving shielded block data (for nodes that store it separately or for light client protocols).

**Message types:**
- `shieldedtx` — announce/relay shielded transactions
- `getshieldeddata` — request shielded block data
- `shieldeddata` — response with shielded bundle data for a block

### Issue 30: Mempool Shielded Weight Calculation

The mempool must correctly account for shielded transaction weight when evaluating fee rates and mempool limits. Current mempool code does not calculate shielded-specific weight.

**Files to modify:**
- `src/txmempool.h/cpp` — add shielded weight calculation
- `src/node/transaction.h` — add shielded tx submission entry point

---

## Category F: Mining and Block Template (Entirely Unbuilt)

### Issue 31: Shielded Transaction Weight in Block Templates

Block template creation (`src/node/miner.cpp`) does not account for shielded transaction weight. The miner cannot correctly sort shielded transactions by feerate or pack them into blocks.

**Files to modify:**
- `src/node/miner.cpp` — include shielded tx weight in block assembly algorithm

### Issue 32: Shielded Fee Estimation

Fee estimation must account for the larger size of shielded transactions. A shielded spend with ring-16 and MatRiCT+ proofs is ~25-35 KB vs ~250 bytes for a typical transparent transaction.

**Files to modify:**
- `src/policy/fees.h/cpp` — shielded fee rate calculation
- `src/policy/policy.h` — shielded transaction policy constants (min relay fee, dust threshold for shielded outputs)

### Issue 33: Coinbase Shielded Output Support

If miners want to receive coinbase rewards directly into the shielded pool, the block template and coinbase transaction construction must support shielded outputs. This is optional (miners can receive transparent and shield later) but desirable.

---

## Category G: Reorg and Disconnect Safety (Entirely Unbuilt)

### Issue 34: Nullifier Set Rollback on DisconnectBlock

When a block is disconnected (reorg), all nullifiers added by that block's shielded transactions must be removed from the nullifier set. The current `NullifierSet` (`src/shielded/nullifier.cpp`) supports batch operations but `DisconnectBlock` in `src/validation.cpp` has no shielded rollback logic.

**What to implement:**
- Track which nullifiers were added per block (for rollback)
- In `DisconnectBlock`, remove those nullifiers from the set
- Ensure the nullifier set state is consistent with the new chain tip

**Files to modify:**
- `src/validation.cpp` — add shielded rollback to `DisconnectBlock`
- `src/shielded/nullifier.h/cpp` — add `RemoveNullifiers()` or batch undo

### Issue 35: Commitment Tree State Rollback

The incremental Merkle tree (`src/shielded/merkle_tree.h`) is append-only. On reorg, commitments added by disconnected blocks must be removed. The frontier-based tree does not natively support truncation.

**What to implement:** Either:
- Store tree snapshots per block in LevelDB for rollback (simpler, more storage)
- Implement a reverse-frontier operation that removes the last N leaves (complex, less storage)
- Store the tree state at each block height in a cache with bounded depth

**Files to modify:**
- `src/shielded/merkle_tree.h/cpp` — add snapshot/restore or truncation support
- `src/validation.cpp` — call tree rollback in `DisconnectBlock`

### Issue 36: Turnstile Balance Rollback

The turnstile pool balance (`src/shielded/turnstile.h`) must be rolled back when blocks are disconnected. The existing `UndoValueBalance()` method exists but is not called from `DisconnectBlock`.

**Files to modify:**
- `src/validation.cpp` — call `UndoValueBalance()` in `DisconnectBlock`

### Issue 37: Wallet Witness and Note State Rollback

On reorg, the wallet must:
1. Un-spend notes whose nullifiers were in disconnected blocks
2. Remove notes received in disconnected blocks
3. Roll back Merkle witnesses to pre-reorg state

**Files to modify:**
- `src/wallet/shielded_wallet.h/cpp` — add `DisconnectBlock()` handler
- Connect to `CValidationInterface::BlockDisconnected`

---

## Category H: Test Coverage (Mostly Absent)

### Issue 38: MatRiCT+ Proof System Tests

The ring signature, balance proof, and range proof have zero real cryptographic tests. Need:
- Known-answer test vectors (construct by hand for small parameters)
- Soundness tests: forged signatures must fail verification
- Completeness tests: honestly generated proofs must verify
- Zero-knowledge spot checks: response distributions must be statistically close to ideal
- Rejection sampling correctness: verify acceptance rates match theoretical predictions

### Issue 39: Consensus Integration Tests

No tests verify the full `ConnectBlock` path for shielded transactions. Need:
- Valid shielded block acceptance
- Invalid proof rejection
- Double-spend (duplicate nullifier) rejection
- Invalid anchor rejection
- Turnstile overflow rejection
- Shielded + transparent mixed transaction handling

### Issue 40: Wallet Functional Tests

No tests for shielded wallet operations. Need:
- Note detection via scanning
- Shielded balance computation
- Shielded spend construction
- Shield and unshield round-trips
- Witness update correctness
- Reorg handling (note disappearance, witness rollback)

### Issue 41: RPC Functional Tests

No tests for z_* RPC commands. Need Python functional tests (in `test/functional/`) covering:
- `z_getnewaddress` → `z_getbalance` → `z_sendmany` flow
- `z_shieldfunds` → `z_listunspent` → transparent unshield flow
- `z_mergenotes` consolidation
- `z_exportviewingkey` / `z_importviewingkey` round-trip
- Error cases (insufficient balance, invalid address, etc.)

### Issue 42: P2P and Mempool Tests

No tests for shielded transaction relay. Need:
- Shielded tx relay to `NODE_SHIELDED` peers
- Rejection of shielded tx relay to non-shielded peers
- Mempool nullifier conflict detection
- Rate limiting enforcement
- Invalid proof rejection before relay

---

## Complete Summary: All Categories

### Production-Ready Components (can ship today)

| Component | Location | Status |
|-----------|----------|--------|
| Incremental Merkle tree | `src/shielded/merkle_tree.h/cpp` | Complete, 786 lines of tests |
| Turnstile accounting (math) | `src/shielded/turnstile.h/cpp` | Correct (needs reorg wiring) |

### Scaffold/Stub Components (exist but non-functional)

| Component | Location | Status |
|-----------|----------|--------|
| Note/nullifier structs | `src/shielded/note.h/cpp` | Basic stubs |
| ML-KEM note encryption | `src/shielded/note_encryption.h/cpp` | API skeleton |
| Bundle structure | `src/shielded/bundle.h/cpp` | Implemented, needs binding sig resolution |
| Lattice arithmetic | `src/shielded/lattice/*.h/cpp` | Partial, NTT reusable from Dilithium |
| Ring signature | `src/shielded/ringct/ring_signature.cpp` | **Scaffold only — trivially "verifies"** |
| Balance proof | `src/shielded/ringct/balance_proof.cpp` | Scaffold |
| Range proof | `src/shielded/ringct/range_proof.cpp` | Scaffold |
| MatRiCT+ orchestration | `src/shielded/ringct/matrict.cpp` | Calls scaffold sub-proofs |
| Consensus validation | `src/shielded/validation.h/cpp` | Stub checks only |

### Entirely Unbuilt Components

| Component | Estimated Effort |
|-----------|-----------------|
| **A: Shielded crypto fixes** (Issues 1-6) | 20-30 weeks (MatRiCT+ dominates) |
| **B: ML-DSA transition tooling** (Issues 7-11) | 4-8 weeks |
| **C: Wallet integration** (Issues 12-16) | 8-12 weeks |
| **D: Shielded RPCs** (Issues 17-26) | 4-6 weeks |
| **E: P2P protocol** (Issues 27-30) | 2-3 weeks |
| **F: Mining/block template** (Issues 31-33) | 1-2 weeks |
| **G: Reorg safety** (Issues 34-37) | 2-3 weeks |
| **H: Test suite** (Issues 38-42) | 6-10 weeks (parallel with above) |
| **External security audit** | 8-12 weeks |
| **Total estimated** | **40-75 weeks from current state** |

### Dependency Graph

```
                        ┌─────────────────────────┐
                        │  A2: MatRiCT+ impl      │
                        │  (critical path,         │
                        │   20-30 weeks)           │
                        └────────┬────────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          ▼                      ▼                      ▼
  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐
  │ A1: Spend    │    │ A4: Binding sig  │    │ A6: Ring member  │
  │ auth fix     │    │ resolution       │    │ selection        │
  │ (in MatRiCT+)│    │ (in MatRiCT+)   │    │ (parallel)       │
  └──────────────┘    └──────────────────┘    └──────────────────┘
                                                       │
          ┌────────────────────────────────────────────┘
          ▼
  ┌──────────────────┐
  │ C12-16: Wallet   │◄──── needs working proofs + ring selection
  │ integration      │
  └───────┬──────────┘
          │
  ┌───────▼──────────┐    ┌──────────────────┐
  │ D17-26: RPCs     │    │ E27-30: P2P      │◄──── independent
  └───────┬──────────┘    └───────┬──────────┘
          │                       │
          └───────────┬───────────┘
                      ▼
              ┌──────────────────┐
              │ H38-42: Tests    │◄──── parallel with all above
              └──────────────────┘

  Independent tracks (can proceed in parallel with everything):
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │ A3: Spec fix │  │ A5: CTV fix  │  │ B7-11: ML-DSA│  │ F31-33:      │
  │ (5 min)      │  │ (1-2 weeks)  │  │ transition   │  │ Mining       │
  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘

  G34-37 (Reorg safety) can proceed once the data structures exist but
  should be tested alongside wallet integration.
```
