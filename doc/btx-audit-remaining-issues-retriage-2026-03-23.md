# BTX Audit Remaining Issues Re-Triage and Fork Assessment

**Date:** 2026-03-23  
**Scope:** unresolved audit items after the remediation work recorded in `doc/btx-audit-reassessment-remediation-plan-2026-03-23.md`  
**Primary sources:** `../_audit/20260323/btx-audit-master-status-2026-03-23.md`, `../_audit/20260323/btx-audit-review-reassessment-2026-03-23.md`, plus the individual Track A/B/C, broader-assessment, regtest, and addendum files under `../_audit/20260323/`

## Purpose

This document does four things for the **remaining** audit backlog:

1. Re-triages the unresolved items based on the underlying descriptions, not only the stale consolidated status file.
2. Re-classifies fork and restart implications after the reassessment and the fixes already implemented on this branch.
3. Produces a priority order biased toward real security and privacy risk.
4. Consolidates the detailed investigation of the remaining fork-sensitive findings into the same planning record.

## High-Level Conclusions

1. **No remaining validated issue requires a chain restart as a technical necessity.**
2. No remaining issue currently justifies an active hard-fork remediation plan.
3. There is no longer an active unresolved fork-sensitive remediation item in the remaining set.
4. The highest remaining security/privacy issues are being deferred for later decision/work:
   - `BA-002`
   - `BA-003`
5. A **restart remains only a policy choice**, for example:
   - if the chain is still low-value / prelaunch and operators want to discard historical privacy leakage rather than just stop adding more.

## Remaining Set Definition

This document tracks only the unresolved backlog. Items already implemented on the current remediation branch are recorded in `doc/btx-audit-reassessment-remediation-plan-2026-03-23.md` and are intentionally omitted from the active planning set here.

Items already fixed earlier, downgraded, validated as OK, or superseded by narrower implemented work are likewise omitted unless they are needed for context.

`C-002` is also omitted from the unresolved set. The local protocol documentation now establishes the CT monomial challenge as an intentional launch-surface design tied to the current `σ` and response-width parameters, so it is closed here as an audit documentation and re-triage item rather than carried as active remediation work.

`BA-001` is likewise omitted from the unresolved set. The current public wire format already serializes the same structural metadata that raw transaction size would reveal, so byte-size analysis adds little incremental leakage once a parser is available.

`P2-004` is also omitted from the unresolved set. The live serial-number construction does expose the raw polynomial `sn = <b_1, s>` before that polynomial is hashed into the nullifier, and `b_1` is globally fixed by the current `0xAA` serial-number commitment-key seed. But the spend secret is derived from each note's secret material rather than reused as a long-lived account key, and the current system never varies `b_1` across contexts. In practice that means the network sees one fixed public linear projection of a one-note secret key, not an accumulating set of independent equations against a reused secret. That is too speculative and low-leverage to keep as active remediation work on the current launch surface.

`BA-005` is also omitted from the unresolved set on the current branch. `z_exportviewingkey` no longer returns `spending_pk_hash`, and the preferred `z_importviewingkey` path now takes the shielded address instead of asking callers to pass the linkage hash directly. The legacy hash form remains accepted only as a compatibility path for older tooling.

`M-002` is also omitted from the unresolved set. `inv_mod_q` is not constant-time in isolation, but the current live call sites are the public monomial-challenge inversion path in `ct_proof.cpp` and the one-time public Vandermonde precomputation in `ntt.cpp`. The current audit material does not show a secret-dependent call path.

`M-006` is also omitted from the unresolved set. The code uses one HKDF salt for note-encryption key, nonce, and bound-note derivations, but it already separates those derivations with distinct `info` labels. Under HKDF that is sufficient domain separation, so changing salts now would create note-encryption compatibility churn without addressing a real security break.

`M-007` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: note plaintext is now serialized directly into secure-allocator buffers for encryption, and decryption reads from the secure plaintext buffer without first copying it through `DataStream`.

`M-014` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the verbose SMILE proof-shape and verifier-step diagnostics in the wallet/proof paths no longer log at the default level and are now available only under debug-gated validation logging.

`M-016` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: new SMILE proofs stop emitting the legacy Rice witness codec, and a height-gated consensus rule rejects Rice-coded proof vectors at `51350`.

`M-023` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: `NullifierSet::Remove` now decrements the diagnostic nullifier count only for nullifiers that actually existed, so missing or duplicate erase requests no longer drift the counter between restarts.

`P4-012` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the persisted shielded-state blob now uses an explicit versioned header plus presence flags for optional fields, while the reader keeps backward compatibility with the legacy and pre-fix positional layouts. That removes the fragile "read whatever bytes remain" logic from newly written local state.

`M-005` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the unused `ScalarSlotInnerProduct` stub that returned a zero polynomial has been removed from the public NTT interface entirely, so there is no longer a silent wrong-result helper waiting to be called by mistake.

`M-018` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: `SmilePoly::operator==` now compares all coefficients before returning instead of short-circuiting on the first mismatch, so the helper no longer carries avoidable position-of-first-difference timing behavior.

`T3-017` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the shielded address-derivation log that included `(account, index)` metadata now emits only under debug-gated wallet logging instead of the default log level.

`RT-003` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: startup logs no longer print freshly generated LevelDB obfuscation key material in plaintext. The remaining obfuscation logging only identifies the path being initialized, not the key bytes themselves.

`P1-009` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the lazy NTT lookup tables now use `std::call_once` instead of unsynchronized static booleans, and the SMILE poly tests now include a concurrent roundtrip smoke test that exercises first-use initialization from multiple threads.

`P1-015` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the SMILE numeric hash / Fiat-Shamir domains are now defined in a shared domain-separation header and consumed from there instead of being repeated as scattered magic integers across `bdlop.cpp`, `membership.cpp`, `ct_proof.cpp`, and `public_account.cpp`.

`EP-001` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the wallet bridge now calls a fallible `TryProveCT` entry point and stops self-verifying ambiguous default-constructed proofs when the prover rejects or exhausts its retry budget. The legacy `ProveCT` wrapper remains only for older internal callers and tests that still treat failure as an empty proof object.

`BA-006` is also omitted from the unresolved set. `z_verifywalletintegrity` and the bundled `z_verifywalletintegrity.json` snapshot are authenticated admin/operator surfaces whose job is to report exact wallet state before backup and after restore. The exact key/note counts and scan height are real metadata, but reducing their precision would mostly weaken the integrity/backup diagnostic value for legitimate operators rather than meaningfully improve privacy after an authenticated RPC compromise.

`M-019` / `TS-004` are also omitted from the unresolved set. The existing `Q - 100` balanced-amount probe is not a live inflation boundary in the BTX design: `EncodeAmountToSmileAmountPoly` intentionally supports the full nonnegative `int64` domain, the actual shielded transaction path applies `MoneyRange` checks at the bundle / note / consensus layers, and the real modular-wrap / overflow attack cases are already asserted in the D5 adversarial tests. Keeping the large-balanced-amount test informational is therefore acceptable here.

`M-020` / `TS-015` are also omitted from the unresolved set because they have been worked on and resolved on the current branch: the dispatch path already rejects duplicate serial numbers with `bad-smile2-proof-duplicate-serial-number`, and the deep adversarial tests now assert that rejection directly instead of conditionally passing when only one of the CT or dispatch layers notices the duplication.

`TS-007` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the CT tests now cover both degenerate ring ends directly. `N = 0` is rejected cleanly at the prover entry point, while `N = 1` is documented as a valid proof-layer edge case that still proves and verifies coherently even though wallet policy requires a much larger live anonymity set.

`TS-016` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the CT tests now cover balanced mixed zero-amount cases in addition to the existing `0 -> 0` transaction probe. A transaction with a zero-valued input plus a nonzero input, and a transaction with a zero-valued output plus a nonzero output, both now prove and verify explicitly.

`TS-008` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the direct-send builder now has an explicit regression test for the zero-output / fee-only case, and it rejects that shape deterministically with `bad-shielded-v2-builder-output-count`. The live transaction layer therefore treats "all value to fee" shielded sends as invalid structure before proof construction instead of leaving the case implicit.

`TS-005` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the real-world timing probes now report large timing ratios as advisory warnings instead of hard pass/fail assertions. That keeps the smoke coverage for obvious regressions while acknowledging that wall-clock timing checks are too noisy to serve as reliable CI gates.

`TS-010` is also omitted from the unresolved set. The live arithmetic tests already assert the corrected `add_mod_q` semantics directly in `smile2_edge_case_tests.cpp`, including `add_mod_q(Q - 1, 1) == 0`; the comprehensive-gap audit note reflects the older pre-fix snapshot rather than the current tree.

`TS-014` is also omitted from the unresolved set. The current functional coverage in `wallet_shielded_encrypted_persistence.py` already locks an encrypted wallet, asserts that shielded key import fails while locked, asserts that shielded send fails while locked, then unlocks and confirms shielded operations succeed again after reload. That is the locked/encrypted-wallet behavior the audit entry was asking for.

`TS-017` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the SMILE `v2_send` proof tests now generate several distinct valid direct-send fixtures, run them through `ParseV2SendProof` plus `ExtractBoundNullifiers`, and assert that the bound nullifiers remain unique across transactions. That closes the audit's “dispatch-path uniqueness” gap without changing the underlying nullifier design.

`TS-018` is also omitted from the unresolved set because it has been worked on and resolved on the current branch: the shielded validation checks now include a `v2_send` anchor-tampering case that rewrites the spend anchor / per-spend merkle anchor, recomputes the bundle digests, and asserts that the stale proof is rejected under the wrong anchor context.

`M-010` is also omitted from the unresolved set. The current encrypted-wallet persistence path already preserves the last good encrypted blob when the wallet is locked, refuses to overwrite that blob with an empty keyset set on a later unlocked persist, and rehydrates spend authorities from persisted or derived state on demand. That removes the stale-state overwrite path the audit was concerned about; the residual cost is at most a heavier local recovery/rescan path, not silent loss of spend authority state.

`P4-018` is also omitted from the unresolved set. The current `fSync=true` writes in the nullifier DB are an intentional durability choice, not a latent integrity bug: the tradeoff is slower block connect/disconnect I/O in exchange for straightforward crash consistency. A future batching optimization could still be worthwhile, but it is not an active audit remediation item.

`T3-013` is also omitted from the unresolved set. `BuildV2SendTransaction` still accepts the spending key as a non-owning `Span`, but the live caller already sources that material from a cleansing wrapper and the current downstream path does not duplicate it into long-lived non-secure storage. That leaves a style/auditability concern, not a demonstrated remaining leakage issue.

## Cross-Check Against The Source Packet

The consolidated master-status file is useful as a starting point, but it is both **stale** and **incomplete** for remaining-work planning.

### Stale classifications that should not drive the remaining backlog

- `H-005` should not remain framed as a clearly live production-path issue.
- `H-006` should not remain framed as "SmileSecretKey never zeroed" in that older broad form.
- The blanket claim that no soft forks are possible is too strong after the reassessment.

### Still-open source findings that are not tracked cleanly in the master summary

These should remain on the backlog even though they are absent or underrepresented in the master file:

- `P4-018` multiple `fSync=true` writes per block connect/disconnect
- test findings omitted from the master roll-up:
  - `TS-001`
  - `TS-002`
  - `TS-003`
  - `TS-006`
  - `TS-007`
  - `TS-010`
  - `TS-012`
  - `TS-013`
  - `TS-015`
  - `TS-016`
  - `TS-017`
  - `TS-018`

## Re-Triage: Security / Privacy / Consensus Backlog

| ID | Reassessed severity | Why it still matters | Fork class | Restart? | Priority |
|---|---|---|---|---|---|
| `BA-002` | Medium privacy | The broader assessment saw exact shielded fees clustering into recognizable per-shape bands, for example 1-in-2-out sends in a unique 64,228-64,275 sat band and a 3-output send at 79,561 sat. Because the exact fee is exposed on-chain as `value_balance`, it remains a cheap cross-layer fingerprint. Wallet-side fee bucketing is straightforward and no-fork, but it is deferred because it changes fee policy rather than consensus and cannot heal historical fingerprints already on-chain. | No fork | No | `P1` |
| `BA-003` | Low-Medium privacy | The audit captured nodes advertising `SHIELDED` in the version-handshake service bits to every peer, which makes shielded-capable infrastructure easy to map and selectively monitor. Making that bit optional or removing it is a P2P-only change, but it is deferred because it is a network-policy / product decision rather than a correctness fix. | No fork | No | `P2` |
| `M-003` | Low-Medium correctness | `DetRng::GaussianSample` still uses Box-Muller over `double` (`sqrt` / `log` / `cos` / `round`), so different libm / CPU combinations can change rejection-sampling retry counts and therefore deterministic proof bytes across x86/ARM platforms. Replacing it with an integer-only discrete Gaussian is prover-side only, but it is deferred because it changes deterministic prover behavior and needs an explicit sampler choice. | No fork | No | `P3` |

## Re-Triage: Local Integrity / Engineering Backlog

These items still matter, but they are not the first security/privacy priorities.

After this pass, only one item remains active in this backlog slice: `P1-010`. It is being deferred for later decision/work because the observed bias is mathematically real but negligible in practice, while a clean exact-uniform replacement would change deterministic SMILE hash-to-polynomial / challenge derivation behavior and therefore should only be done with an explicit compatibility/versioning plan.

| ID | Reassessed severity | Notes | Fork class | Restart? | Priority |
|---|---|---|---|---|---|
| `P1-010` | Low | The audit measured a real modulo bias in `uint32_t % Q`: because `Q = 2^32 - 959`, coefficients `0..958` occur twice as often as `959..Q-1`, a bias of about `959 / 2^32 ~ 2^-22` per coefficient. The same pattern appears in `ExpandPoly` and related deterministic SMILE hash-to-polynomial / challenge helpers. The effect is negligible in practice, but an exact-uniform replacement would change deterministic expansion/challenge outputs, so it is deferred until there is a compatibility/versioning plan. | No fork | No | `P4` |

Low-level source findings such as `SC-002`, `SC-004`, `P2-018`, and `P4-016` were reviewed and kept as low-priority engineering notes rather than promoted into the main security backlog.

## Re-Triage: Test / Validation Backlog

The test backlog is larger than the master summary suggests. None of these items need a fork or restart, but several are important for confidence in future consensus/privacy work.

### High-priority test debt

| ID | Reassessed severity | Notes | Priority |
|---|---|---|---|

### Medium-priority test debt

| ID | Reassessed severity | Notes | Priority |
|---|---|---|---|
| `TS-001` | Medium | The membership ZK test still uses only `N=50` proofs, flags outliers only when coefficient means deviate by more than `50%`, and still allows up to `32` outlier positions. The audit recommendation was `N >= 1000` with a real KS / chi-squared style test. That is deferred because it needs an explicit CI/runtime budget and stronger test-method decision. | `P2` |
| `TS-002` | Medium | The CT ZK test is even weaker than `TS-001`: it still uses only `N=20` proofs with the same `50%` deviation threshold. The audit recommendation was the same `N >= 1000` style statistical upgrade. It is deferred for the same runtime/methodology reason as `TS-001`. | `P2` |
| `TS-006` | Medium | The suite proves `1-in-16-out` and separately computes the `16-in-16-out` cost constant (`1840`), but it still does not generate and verify an actual `16-in-16-out` CT proof end to end. That leaves max-capacity buffer / amortization / aux-layout bugs less exercised. The audit recommendation is still correct, but this is deferred because a real max-capacity prove/verify case is a test-runtime budget decision rather than a trivial addition. | `P2` |
| `TS-012` | Medium | The lower-level pieces exist separately, for example seed uniqueness, serial determinism, and nullifier-set duplicate detection, but there is still no single end-to-end test that submits the exact same valid proof twice and observes the consensus-path replay rejection. The audit recommendation to cover replay through `AnyExist` / block acceptance remains valid; it is deferred because it needs a dedicated combined harness rather than a small assertion change. | `P2` |
| `TS-013` | Medium | The current tree covers single-block connect/disconnect rollback and short functional shielded reorg recovery, but it still lacks the audit's requested dedicated `10+` block deep reorg case that verifies rolled-back nullifiers become spendable again, the merkle root rewinds correctly, and pool balances stay consistent. That remains deferred because it is a longer-running functional/harness task. | `P2` |

### Lower-priority test debt

| ID | Reassessed severity | Notes | Priority |
|---|---|---|---|
| `TS-003` | Low | The audit smoke tests still use only `N=30` proofs and very loose checks, for example `a10_zk_z0_distribution` allows `5 * tol` around the mean and `a11_zk_index_indistinguishability` only checks a `< 10%` relative mean gap. The audit recommendation was `N >= 500` with tighter bounds. This remains deferred until the broader ZK test-budget / methodology decision is made. | `P3` |
| `TS-009` | Low | Two comprehensive-gap NTT tests, `s6_ntt_unreduced_coefficients` and `s6_ntt_roundtrip_negative_coefficients`, still end in `BOOST_CHECK(true)` after documenting that either tolerant or intolerant behavior is "acceptable." The audit is right that they provide no regression protection in that form. This stays deferred because tightening them first requires an explicit contract decision on whether raw unreduced / negative NTT inputs are meant to be supported or rejected. | `P3` |

`TS-011` is not carried as a separate backlog item because it documents challenge-space characteristics for the already-clarified `C-002` design choice, not a standalone missing fix.

## Fork / Restart Assessment

### Remaining fork-sensitive set

After reviewing the current tree and the source audit packet, the unresolved fork-sensitive set is:

- none in the currently unresolved backlog

Everything else in the remaining backlog is wallet-side, runtime, RPC, logging, local-state, or test work.

### Closed clarification on `C-002`

`C-002` is no longer carried in the active remaining backlog.

The local documentation is enough to show that the monomial CT challenge is deliberate and coupled to the current launch-surface parameters, not an accidental mismatch:

- `src/shielded/smile2/ct_proof.h` documents that the CT prover remains on a monomial Fiat-Shamir surface because the live response-width parameters on wire are still tuned for it.
- `src/shielded/smile2/ct_proof.cpp` documents the same monomial weak-opening assumption directly at the rejection-sampling and challenge-construction sites.
- `src/shielded/smile2/params.h` documents the parameter rationale: monomial `c = ±X^k` keeps `||c·r||∞ <= 1` for ternary `r`, permitting the current small `σ`.

That is enough to close the audit issue as a documentation-backed design clarification. It is not, by itself, a formal cryptographic proof, so any deeper theorem-level review belongs in future assurance work rather than the active remediation plan.

### Closed clarification on `BA-001`

`BA-001` is also no longer carried in the active remaining backlog.

The original audit observation that shielded transaction size correlates with structure is true, but in the current BTX design that leakage is mostly redundant with already-public wire data:

- `TransactionHeader` already exposes the transaction family, proof-shard count, and output-chunk count.
- `SendPayload` explicitly serializes the spend count and output count.
- batch-family payloads explicitly serialize the counts of consumed spends, ingress leaves, and reserve outputs.
- `proof_payload` is length-prefixed, so proof byte size is already parser-visible without relying on outer transaction size.

Because this repo is public and any observer can run the same parser as a node, the incremental information added by raw total byte size is minimal. A true count-hiding wire redesign would still be a possible future privacy project, but it is not a worthwhile active audit remediation item.

### Resolved `BA-005`

`BA-005` has been worked on and resolved on the current branch.

The original issue was real: exporting `spending_pk_hash` through `z_exportviewingkey` unnecessarily handed callers a stable linkage identifier across addresses derived from the same spending authority.

That exposure is now removed from the preferred RPC and backup surfaces:

- `z_exportviewingkey` now returns the shielded address, viewing key, and KEM public key, but not `spending_pk_hash`
- `z_importviewingkey` now accepts the shielded address as the preferred third argument and derives the linkage hash internally
- the legacy raw-hash import form remains accepted only for compatibility with older tooling
- wallet-bundle viewing-key exports now omit `spending_pk_hash` as well

This keeps the watch-only import flow functional without continuing to promote the linkage hash as a first-class exported artifact.

### Resolved `M-014`

`M-014` has been worked on and resolved on the current branch.

The original issue was real: SMILE wallet/proof code paths were emitting transaction-shape and verifier-step diagnostics through `LogPrintf`, which meant they appeared at the default log level and were exposed to ordinary node operators and any downstream log collection.

That verbose output is now debug-gated instead:

- `CreateSmileProof` logging in `wallet_bridge.cpp` now uses `LogDebug(BCLog::VALIDATION, ...)`
- `VerifyCT` and related `ProveCT` diagnostics in `ct_proof.cpp` now use `LogDebug(BCLog::VALIDATION, ...)`
- the information remains available when an operator explicitly enables validation-category debug logging, but it no longer leaks by default

### Resolved `M-007`

`M-007` has been worked on and resolved on the current branch.

The original issue was real: note plaintext was serialized through `DataStream` and only then copied into `secure_allocator` storage for encryption, so sensitive note bytes briefly existed in the ordinary `DataStream` backing buffer first.

That extra copy is now removed:

- encryption now serializes notes and padded bound-note plaintext directly into `secure_allocator` byte vectors
- decryption now parses from the secure plaintext buffer with `SpanReader` instead of copying it back into `DataStream`
- the remaining plaintext lifetime stays inside the secure buffer and is still explicitly cleansed after use

### Deferred `BA-002`

`BA-002` remains active and should be kept for later decision rather than implemented ad hoc.

The issue is real: `value_balance` is serialized on-chain, and for common `V2_SEND` flows it exposes the exact fee or exact net transparent value movement. In practice that gives observers a cheap cross-layer fingerprint, especially when wallet fee estimation produces slightly different exact values across otherwise similar transactions.

The blocker is that there is no one obviously correct mitigation without choosing a wallet policy:

- quantize fees to fixed buckets
- force a narrower set of standard fee targets
- pad or normalize transaction flows so `value_balance` carries less distinguishing information

Each of those changes affects user-visible economics, recipient amounts, or transaction construction behavior. They also permanently change wallet-side output patterns without fixing historical on-chain fingerprints. So this should stay open until there is an explicit fee/privacy policy decision on the desired bucketing strategy and acceptable cost tradeoff.

### Deferred `BA-003`

`BA-003` remains active and should also stay open for an explicit networking decision.

The issue is real: BTX nodes advertise `NODE_SHIELDED` in the version handshake by default, and the relay layer uses that bit to decide which peers are eligible for shielded transaction relay. That makes shielded-capable nodes easy to map and target at the network layer.

The blocker is that the service bit is not just cosmetic metadata in the current design. It is part of how peers discover relay capability:

- removing it entirely changes shielded peer selection semantics
- making it optional creates interoperability and operator-policy questions
- keeping relay gated on the bit while turning it off by default risks degrading shielded propagation

So this is a real privacy tradeoff between network discoverability and explicit relay capability signaling. It should stay active until there is a clear P2P policy on whether BTX wants default-on advertisement, opt-in advertisement, or a different capability-discovery mechanism.

### Deferred `M-003`

`M-003` remains active and should stay open pending a cryptographic implementation decision.

The issue is real in the narrow sense identified by the audit: the prover still uses floating-point Box-Muller sampling for Gaussian masks, so deterministic proof generation can diverge across architectures or standard-library implementations even though the verifier stays consensus-safe.

But replacing it is not a small mechanical edit. A proper fix means choosing and validating an integer-only sampler, such as CDT or Knuth-Yao, and then rechecking the surrounding rejection-sampling and proof-size behavior against the live SMILE parameters. That is cryptographic implementation work, not just a local cleanup.

So this item should remain deferred until there is an explicit decision on the replacement sampler and enough review bandwidth to validate it as more than a portability tweak.

### Closed clarification on `M-006`

`M-006` is no longer carried in the active remaining backlog.

The code does use the same HKDF salt string across multiple note-encryption derivations, but the actual separation is already provided by distinct `info` labels:

- `BTX-Note-Encryption-Key-V2`
- `BTX-Note-Encryption-Nonce-V2`
- the separate bound-note `rho` / `rcm` derivation labels

That is the standard HKDF domain-separation surface. Reusing the salt here does not collapse the key and nonce derivations into the same output because the `info` strings differ. As a result, the audit finding is best treated as a low-value stylistic preference rather than an active security issue.

Changing the salt values now would also change note-encryption outputs and bound-note derivation behavior for no real security gain, so it is not worthwhile remediation work for the current launch surface.

### Closed clarification on `M-002`

`M-002` is no longer carried in the active remaining backlog.

The primitive-level observation is correct: `inv_mod_q` uses repeated square-and-multiply and is not written as a constant-time inversion helper. But the live BTX call sites are currently limited to public values:

- monomial challenge inversion in `ct_proof.cpp`, where the coefficient comes from the Fiat-Shamir challenge and is therefore public
- the one-time Vandermonde inverse precomputation in `ntt.cpp`, which operates only on public slot roots and matrix entries derived from them

So the issue only becomes security-relevant if a future code path starts calling `inv_mod_q` on secret inputs. The right response on the current launch surface is to record that constraint, not to treat the current implementation as an active side-channel vulnerability.

### Closed clarification on `P2-004`

`P2-004` is also no longer carried in the active remaining backlog.

The audit's algebraic description is accurate, but the practical conclusion was too aggressive for the live BTX design.

What is exposed:

- the raw on-wire serial polynomial is `sn = <b_1, s> = sum_j b_1[j] * s_j`
- `s` is the current note's SMILE secret key, consisting of `4` short polynomials in the degree-`128` ring
- `b_1` is the first BDLOP message vector from a commitment key deterministically generated from the fixed serial-number seed `0xAA`
- the proof serial bytes are public, and the nullifier is the hash of that polynomial rather than a replacement for it

What that means in practice:

- one spend reveals one fixed public linear projection of the note's secret key
- because the serial is one polynomial, that gives `128` ring-coefficient equations, not the full `4 x 128` ternary secret coefficients
- the remaining search space is still enormous, matching the source audit's own observation

Why this is closed for the live backlog:

- the spend key is derived from each note's secret `rho` / `rcm` material rather than reused as a long-lived account key
- honest flow spends a note once, so the same secret does not keep producing fresh observations
- the implementation keeps `b_1` globally fixed, so the system does not accumulate independent linear projections of the same key across different serial-number contexts
- the source report itself does not present a practical exploit against the live one-note-one-key model

The remaining lesson is architectural, not an active fix item: future work should avoid reusing the same spend secret under multiple serial-derivation rules or multiple public `b_1` vectors. If the project ever changes the serial-number derivation itself, that remains hard-fork-sensitive because nullifier semantics would change.

### Resolved `M-016`

`M-016` has been worked on and resolved on the current branch.

It was a real verifier availability issue: the legacy Rice witness codec allowed a crafted proof to force unnecessarily expensive unary-prefix decode work before later checks ran. That issue is now addressed on the current branch in two layers:

- canonical SMILE proof serialization no longer emits Rice-coded Gaussian witness vectors
- upgraded consensus parsing rejects Rice-coded SMILE proof vectors at and after height `51350`

This is implemented as a soft fork without a chain restart. Historical pre-activation blocks remain valid, while post-activation Rice-coded proofs are explicitly invalid for upgraded nodes.

### Summary table

No unresolved finding in the current remaining set still needs fork planning.

### Compatibility model by fork class

#### Soft fork

Use when:

- the already-serialized bytes remain the same
- upgraded nodes only add a stricter rule over those bytes

There is no unresolved soft-fork item left in the current remaining set.

Compatibility:

- old blocks and old transactions remain valid forever
- the pre-activation historical chain stays recognized
- old nodes can still parse post-activation transactions
- old nodes may relay or mine transactions upgraded nodes reject

### Restart conclusion

For the still-open backlog, a restart is **not technically required**.

## Recommended Execution Order

The list below is the recommended **execution order**, not merely a restatement of severity. It favors real risk reduction with minimal deployment friction.

1. Land the remaining no-fork privacy wins.
   - `BA-002`
   - `BA-003`
2. Close the highest-value test gaps.
   - start with `M-019` / `TS-004`, `M-020` / `TS-015`, `TS-001`, `TS-002`, `TS-013`, and `TS-018`

## Bottom Line

After the current remediation branch, the remaining backlog is materially smaller and much less restart-sensitive than the original packet implied.

- **No remaining issue requires a restart.**
- The next practical work should be:
  - landing the no-fork privacy wins,
  - and then closing the remaining privacy, runtime, and test backlog items.
