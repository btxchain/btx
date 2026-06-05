# External Crypto Audit Scope — SMILE2 CT-proof soundness (C-002 completion)

Purpose: independently establish (or refute) the knowledge-soundness of BTX's active shielded confidential-
transaction proof (SMILE2 / SMILE-based, BDLOP commitments, ring Z_q[X]/(X^128+1), q=2^32−959). This is
**urgent and mandatory** because: (1) the *entire existing shielded pool* already relies on it; (2) 0.30.3 ships
self-service unshield, making it a permissionless, high-volume value-extraction surface; (3) an in-house
conservative fix is NOT possible (see redteam/findings/i5.md — the verifier inverts the challenge, so the
challenge cannot be swapped without an original extractor re-derivation). Our own attempt to break it
(redteam/findings/{f3,e2,x1}.md) is best-effort, not a proof of security.

## The specific concern (f3)
The CT proof gates its commitment **openings** with a **monomial Fiat-Shamir challenge c = ±X^k — only 256
values (2^-8 per-opening knowledge error)**. High-level relations use ~2^128 slot challenges, but the *opening*
an extractor relies on does not. Soundness therefore holds ONLY IF a tight M-SIS reduction exists for this
exact monomial transcript. BTX's own audit flagged this as **C-002 and deferred it without the security
estimate.** The legacy MatRiCT path already replaced an analogous low-entropy challenge with a high-entropy
polynomial one (precedent that this class of gap is real).

## Deliverables required from the auditor
1. **Tight knowledge-soundness/extractor proof** for the SMILE2 CT relation as implemented (not the paper's
   idealization) — including the monomial opening challenge and the `f²+c·f`, `c²·h2` framework relations
   (ct_proof.cpp:3641-3663) and the `InvertMonomialChallenge` inversion (ct_proof.cpp:82,371). State the exact
   extractor and its success probability / slack.
2. **Concrete soundness-error bound** at the live parameters (σ=55/31, 7-bit responses, β0²/β² verifier bounds
   at ct_proof.cpp:3316/3346) — is the per-tx forgery probability negligible (≤2^-128)? Quantify, don't assert.
3. **M-SIS / M-LWE hardness estimate** (BKZ cost) at the live ring/modulus/rank, confirming the binding/hiding
   assumptions the reduction rests on meet the claimed security level.
4. **Verdict + remediation:** either "sound at current params" (with the proof), OR a concrete parameter/
   challenge change WITH the re-derived σ ↔ rejection-rate ↔ β ↔ extractor-slack ↔ security-estimate chain
   (the work i5 showed cannot be guessed in-house), specified precisely enough to implement as a height-gated
   hard fork.
5. **Side-channel note:** the prover is not constant-time (e4/wallet-side) — assess key-extraction risk for
   shielded spending keys.

## Inputs to hand the auditor
- redteam/findings/f3.md (scheme ID + the gap), i5.md (why the swap can't be done in-house + the 5-item list),
  e2.md (Fiat-Shamir/range analysis), e3.md (membership/nullifier), x1.md (the empirical forge attempt + measured
  work factor). Source: src/shielded/smile2/ct_proof.cpp, params.h, src/matmul/... commitments.
- The deferred internal C-002 ticket.

## Interim posture (until the audit returns)
Decision = SHIP self-service unshield fully in 0.30.3. Compensating: max-effort internal adversarial testing
(x1 forge attempt, x2 double-spend/inflation, x3 privacy/DoS/memory) MUST come back clean before release; if x1
finds ANY accepted false-value proof → CRITICAL → do not ship the feature. Keep a turnstile/value-pool monitor
live post-release to detect shielded-pool imbalance (inflation canary).
