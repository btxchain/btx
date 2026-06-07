# BTX shielded pool — formal verification plan & spec

Acting cryptographer, v0.32.0+. This is the **context anchor** for a tiered formal-verification effort
on the BTX shielded value-soundness stack. It defines the properties to verify, the trusted base, the
tools, and a status tracker. It is a *living* document: each tier updates §6.

## 0. Honesty contract (read first)

Formal verification eliminates a *class* of bugs **relative to a spec, under assumptions** — it is
not magic bug-freedom. Three caveats hold throughout and are restated where relevant:

- **Spec-correctness:** a verified implementation of a wrong spec is still wrong. The spec (§2) is
  itself an attack surface and is reviewed as such.
- **Model-to-code gap:** we verify *models* of the consensus logic (SMT/structured proof). Unless a
  step is verified down to the shipped binary (not attempted here), there remains a gap between the
  model and `btxd`. We mitigate by (a) deriving models directly from the cited `file:line`, (b)
  cross-checking against the existing forge harness + unit tests, and (c) keeping models small and
  legible so the model≈code correspondence is auditable by eye.
- **Assumptions:** Module-SIS / Module-LWE hardness at the deployed parameters remain *assumptions*
  (standard, but assumptions). Tier 3 reduces soundness *to* M-SIS; it does not prove M-SIS.

Every claim below is tagged: **[MC]** machine-checked (a solver/checker accepted it), **[PR]**
paper-rigorous (a written proof, not mechanized), **[T]** test-backed (empirical only).

**Rigor standard (per the mandate): every tier is paper-rigorous.** The primary deliverable at all
three tiers is a written proof to academic standards — definitions, lemmas, theorems, complete proofs,
and explicit citations to the source literature: BDLOP commitments (Baum–Damgård–Lyubashevsky–
Oechsner–Peikert, ePrint 2016/997), MatRiCT (Esgin–Zhao–Steinfeld–Liu–Sakzad, CCS'19, ePrint
2019/1287) and MatRiCT+ (Esgin–Steinfeld–Liu, S&P'21, ePrint 2021/545), SMILE (Lyubashevsky–Nguyen–
Seiler, CRYPTO'21, ePrint 2021/564), and the Module-SIS/Module-LWE hardness lineage (Langlois–Stehlé
2015; Lyubashevsky's Fiat–Shamir-with-aborts framework). Z3 is used only to *mechanically discharge
the decidable sub-obligations* (integer-arithmetic invariants, finite ring-identity and
invertibility checks) as machine-checked corroboration of specific lemmas — it never replaces a proof.
Deployed parameters (`src/shielded/smile2/params.h`): d=128, q=2³²−959, l=32 quartic slots, M-SIS/
M-LWE ranks α=β=10, key block k=5/ℓ=4, ternary secrets (η=1), σ_mask=55 / σ_key=31, anon set 2¹⁵.

## 1. Trusted computing base

Trusted (not verified here): the Z3 solver and its theory solvers; Python; the GCC toolchain; the
SHA-256 / Fiat–Shamir random-oracle idealization; M-SIS/M-LWE hardness; that the SMT/abstract models
faithfully transcribe the cited code. Verified: the properties in §2 against those models.

## 2. The spec — properties to verify

Mapped to source. These are the obligations the three tiers discharge.

### S1 — Turnstile (net-supply firewall). `src/shielded/turnstile.{h,cpp}`, enforced `validation.cpp:1082/~6122`.
- **S1.1** `ApplyValueBalance` preserves the invariant `0 <= balance <= MAX_MONEY` whenever it returns
  true, for any `value_balance` with `|value_balance| <= MAX_MONEY`.
- **S1.2** No signed-integer overflow/UB in `ApplyValueBalance` for money-range inputs.
- **S1.3** `UndoValueBalance(v)` is a left inverse of `ApplyValueBalance(v)` on success (reorg-exact).
- **S1.4** Cumulative: total transparent value emitted by unshields can never exceed total shielded
  in (the pool floor is 0) — net new supply = 0. (Follows from S1.1 by induction over blocks.)

### S2 — Unshield velocity cap. `src/shielded/unshield_velocity.{h,cpp}`, enforced `validation.cpp` ConnectBlock.
- **S2.1** `WindowCap(pool, bps)` computes `floor(bps/10000 * pool)`, saturating at MAX_MONEY, with no
  overflow for `pool <= MAX_MONEY`, `bps < 2^16`.
- **S2.2** `UndoBlock(h)` exactly inverts `RecordBlock(h, e)` (reorg-exact): the window state after
  Record-then-Undo equals the state before.
- **S2.3** `WindowTotal(tip, W)` = sum of recorded egress over the half-open window `(tip-W, tip]`
  (exclusive lower bound), and is monotone non-decreasing in the recorded entries.
- **S2.4** Cap soundness: if every connected block satisfies `WindowTotal <= WindowCap(pool_start)`,
  then over any W-block window at most `bps/10000` of the pool is unshielded.

### S3 — value_balance binding (pool delta <-> transparent vout). `consensus/tx_verify.cpp:203-227`.
- **S3.1** The pool decrement equals the transparent value leaving the boundary; a shielded spend
  cannot create transparent value the pool did not hold (ties S1 to real UTXOs).

### S4 — C-002 nullifier (serial<->key) binding. `ct_proof.cpp:3503-3509` + key relation `:3715-3727`.
- **S4.1** Given the verifier's two checks share the *same* response `z0`, and the key opening pins
  `z0` to the genuine secret `s` under M-SIS binding of `A`, the revealed serial equals `<b_sn,s>` —
  i.e. two distinct nullifiers for one note cannot both verify, except by a short M-SIS solution.
- **S4.2** Monomial-difference invertibility: for distinct monomial challenges `c != c'`, `c - c'` is
  a unit in `R_q` (so special-soundness extraction yields a genuine witness / short collision).

### S5 — C-002 value (inflation) binding. `ct_proof.cpp:3847-3890` (STEP 11e + Gamma-validity).
- **S5.1** Gamma-validity is a structural (non-challenge-gated) check; a forged balance carrier
  cannot satisfy `coeffs[1..3]==0 && |digit|<=bound && Eval(Gamma)==0` while encoding an imbalance.
- **S5.2** The balance relation `Sum f[In] - Sum f[Out] + c*enc(fee) - c*Gamma == balance_w` holds iff
  value is conserved, for any single (unit) monomial challenge `c`.

### S6 — Soundness reduction (Tier 3). The protocol's knowledge-soundness error for forging S4/S5 is
`<= q_H * Adv_MSIS(params)`, NOT the 2^-8 monomial knowledge error. (Formalizes F3_MSIS_SOUNDNESS_REDUCTION.md.)

## 3. Tier 1 — accounting invariants  →  Z3 [MC]

Discharge **S1, S2, S3** by SMT. Integer/bitvector models transcribed from the code; Z3 proves the
invariants for *all* money-range inputs (not samples). Artifacts: `tier1/*.py` (Z3), a runner that
exits nonzero on any `sat` counterexample to a negated obligation. CI-friendly.

## 4. Tier 2 — verifier relation soundness  →  Z3 algebra [MC] + structured proof [PR]

Discharge **S4, S5**. The *algebraic, decidable* parts go to Z3 over `GF(q)` / bounded polynomial
arithmetic: S4.2 (monomial-difference invertibility, finite check), S5.2 (the balance identity is a
ring identity), the Gamma-validity arithmetic (S5.1). The *reduction* parts (S4.1 "M-SIS pins z0")
are paper-rigorous, transcribed from the F3 reduction with the algebra mechanized.

## 5. Tier 3 — soundness reduction to M-SIS  →  structured game proof [PR] + mechanized lemmas [MC]

Discharge **S6**. A game-based knowledge-soundness argument (extractor + forking) reducing a forger
to a short-M-SIS solver, written as a sequence of game hops with each *algebraic* hop's identity
checked in Z3. Full mechanization in EasyCrypt/SSProve is out of scope for this pass (no toolchain
available + person-year effort); this tier delivers the rigorous reduction with machine-checked
algebra and an explicit list of the remaining hand-proved lemmas for an external EasyCrypt pass.

## 6. Status tracker

| Obligation | Tier | Method | Status |
|---|---|---|---|
| S1.1 turnstile invariant | 1 | Z3 | **PROVED** |
| S1.2 no overflow | 1 | Z3 | **PROVED** |
| S1.3 undo inverse | 1 | Z3 | **PROVED** |
| S1.4 supply floor (induction) | 1 | Z3+[PR] | **PROVED** |
| S2.1 WindowCap no overflow | 1 | Z3 | **PROVED** |
| S2.2 RecordBlock/UndoBlock inverse | 1 | Z3 | **PROVED** |
| S2.3 WindowTotal window semantics | 1 | Z3 | **PROVED** |
| S2.4 cap soundness | 1 | Z3+[PR] | **PROVED** |
| S3.1 value_balance binding | 1 | Z3 | **PROVED** |
| S4.2 monomial-diff invertibility | 2 | Z3 | **PROVED** |
| S5.2 balance ring identity | 2 | Z3 | **PROVED** |
| S5.1 Gamma-validity | 2 | Z3 | **PROVED** |
| S4.1 serial<->key (M-SIS pins z0) | 2 | [PR]+Z3 | **PROVED** |
| S6 soundness reduction | 3 | [PR]+Z3 | **REDUCED** (PR; algebra MC; §7.1 residual → external EasyCrypt) |

**Tier 1** `tier1/PROOFS.md` + `tier1/accounting_z3.py` (8/8). **Tier 2** `tier2/PROOFS.md` +
`tier2/invertibility.py` (32 640 pairs) + `tier2/relation_z3.py` (8/8). **Tier 3** `tier3/PROOFS.md`
+ `tier3/reduction_z3.py` (H1–H4). All three tiers paper-rigorous; S6's single residual (no off-witness
monomial collapses a framework term that is not itself an M-SIS solution) is assessed-sound and packaged
for external mechanization (`redteam/F3_EXTERNAL_REVIEW_BRIEF.md`).

## 7. Tooling & reproduction

- Z3 4.16 (`pip install --user --break-system-packages z3-solver`). Run the whole suite:
  `python3 formal-verification/run_all.py` (exits 0 iff every [MC] obligation discharges).
- Each artifact prints, per obligation, `PROVED` (negation unsat / exhaustive pass) or a counterexample.
  A green run = all listed [MC] obligations discharged for all inputs in their stated ranges. The
  paper-rigorous theorems live in each tier's `PROOFS.md` and cite the [MC] lemmas by name.
