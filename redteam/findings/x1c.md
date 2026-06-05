# x1c — DEFINITIVE EMPIRICAL VERDICT on the f3 SMILE2 CT forge (verify x1b's candidate-CRIT)

## ★★★ VERDICT: THE FORGE SUCCEEDS — `smile2::VerifyCT` **ACCEPTS** an inflationary proof. CRITICAL. ★★★

x1b's CANDIDATE-CRITICAL reasoning is **CONFIRMED EMPIRICALLY, NOT REFUTED.** The unconditional
binding digests (PRE_H2 / POST_H2 / ROUND1_AUX / combined coin-opening) — the decisive question x1
and x1b left open — **DO NOT catch the forge.** They bind the prover's *own forged* `h2` to itself,
so a self-consistent unbalanced proof passes every check.

**Real verifier output (no placeholder):**
```
./test/rtx1_f3_forge_tests.cpp(269): Entering test case "rtx1_05_forge_unbalanced_fee"
[rtX1-05] FORGE unbalanced in=100 out=100 fee=50 verify = 1 (CRITICAL if 1)
./test/rtx1_f3_forge_tests.cpp(282): error: in "rtx1_05_forge_unbalanced_fee": check !forged has failed
```
`verify = 1` ⇒ `VerifyCT` returned **true** for a proof that declares `public_fee = 50`
(50 sat of transparent payout = `value_balance`) on a truly **balanced in=100 / out=100** spend
whose real surplus is **0**. 50 sat minted from nothing, accepted by the consensus verifier.
**This is deterministic — it accepted the FIRST proof built (work factor 1, not 2^8).**

## What I ran (real, isolated, no fabrication)
- Reused x1's built RelWithDebInfo `test_btx` image `rtx1-tests:latest` (built in docker from
  `/tmp/rtX1/src`, Alpine 3.22, `--target test_btx`), which embeds:
  - harness `src/test/rtx1_f3_forge_tests.cpp` driving `ProveCT`/`VerifyCT` directly (bypasses the
    i3 z_sendmany wallet stack-overflow — confirms i3's "verifier path is reachable in-process");
  - red-team forge hooks in a PRIVATE copy of `src/shielded/smile2/ct_proof.cpp`:
    `rtx1::g_forge_skip_balance` (bypass the prover's `sum_in==sum_out+fee` refusal at ct_proof.cpp:2254)
    and `rtx1::g_forge_zero_carry` (force the h2 balance-carry `delta` to 0 at ct_proof.cpp:2859) —
    identical mechanism to x1b's `rtx1b::g_forge_zero_carry` at the live ct_proof.cpp:2866.
  - i3's 8 MB-stack fix is NOT needed in-process here (the test driver calls `VerifyCT`/`ProveCT` on
    the main test thread, glibc 8 MB stack; no httpworker). No crash in any run.
- Drove the decisive cases as standalone `test_btx --run_test=...` invocations in fresh `rtX1C-*`
  containers off `rtx1-tests:latest`. Each `ProveCT`/`VerifyCT` is real BTX consensus code.

## EMPIRICAL RESULTS (exact, reproduced)
| test | scenario | `VerifyCT` | meaning |
|---|---|---|---|
| rtx1_05 | **FORGE**: hooks on, build proof w/ fee=50 in transcript + zero the −50 carry; true in=out=100 | **= 1 ACCEPTED** | ★ **CRITICAL inflation — forge succeeds, deterministic** |
| rtx1_08 | FORGE (as 05) **+ omega=0 + framework_omega=0** (skip the `!IsZero()` gated checks) | **= 1 ACCEPTED** | ★ forge survives even with the gated relations skipped — the gates are irrelevant to the catch |
| rtx1_10 | control: hooks on but **genuinely balanced** in=150 out=100 fee=50 | = 1 ACCEPTED | sanity — a real balanced proof verifies (forge hooks don't break honest proofs) |
| rtx1_06 | NO hooks: prove honest balanced fee=0, then call `VerifyCT(..., fee=50)` | **= 0 REJECTED** | you canNOT just lie about fee at verify time — fee is FS-bound (transcript/seed mismatch) |
| rtx1_01 | NO hooks: honest balanced fee=0, verify fee=1e6 | = 0 REJECTED | same: naive fee-bump on an honest proof is caught |
| rtx1_03 | NO hooks: honest balanced in=150 out=100 fee=50, verify fee=100 | = 0 REJECTED | same |
| rtx1_02b | omega/fw zeroed on honest proof, verify fee=50 | = 0 REJECTED | zeroing omega alone on an honest proof doesn't forge |
| rtx1_09 | FORGE + zero **fs_seed/seed_c0/seed_c/seed_z** + omega + fw | = 0 REJECTED | zeroing the SEEDS breaks the recomputed-transcript binding ⇒ reject (NOT a defense vs the forge; the real forge in 05/08 never tampers seeds — it is fully self-consistent) |

(rtx1_07 forge-grind quantification was NOT run to completion — each forge ProveCT is ~0.1–2 s and
4096 trials exceeded my budget; I stopped it. The verdict does NOT depend on it: rtx1_05 and rtx1_08
are **deterministic single-shot accepts** — the very FIRST forged proof built was accepted, so the
empirical work factor is **1**, far below the 2^8 the f3 monomial-grind hypothesis would predict. The
forge is not probabilistic.)

## THE EXACT ACCEPTING MECHANISM — why the binding digests LOSE
The decisive question (x1.md L27-32 / x1b): *do PRE_H2@3531 / POST_H2@3665 / the combined
coin-opening digest@3686 catch the fee=50-vs-zero-surplus lie?* **No.** Root cause, traced in
`src/shielded/smile2/ct_proof.cpp` (live source, not the forge copy):

1. **The verifier never independently recomputes `h2` from the committed amounts.** Every use is of
   the prover-supplied `proof.h2`:
   - STEP-1 balance gate (3122-3133): checks `proof.h2.coeffs[0..3]==0`. The forge zeroed the carry
     ⇒ `proof.h2 = g0 + live_y_sum`, coeffs[0..3]=0 ⇒ **STEP-1 PASSES by construction.**
   - framework relation (3656-3663): `bracket = framework_sum − c·f[G] − c²·proof.h2`;
     `lhs = α·bracket + bin_check + f[Psi]` — uses the SAME forged `proof.h2`.
   - POST_H2 binding digest (3665-3671): recomputed over that SAME `lhs` ⇒ equals the prover's
     `post_h2_binding_digest` (the prover computed it over its own forged lhs at 2932-2939).
     **Digest matches ⇒ no catch.**
2. **`public_fee` is bound only into the TRANSCRIPT/seed, never as an arithmetic constraint on
   `h2`.** Prover inserts fee at ct_proof.cpp:2319; verifier inserts the IDENTICAL fee at 3213.
   The forge prover builds the *entire* transcript with fee=50, so `fs_seed`/`seed_c0`/`seed_c` all
   match the verifier's recomputation — the proof is self-consistent. The −50 that fee=50 *should*
   have forced into the h2 carry is simply dropped, and **nothing else in the verifier re-derives
   that the (amounts, fee) tuple must balance.** The balance is enforced ONLY through
   `h2.coeffs[0..3]==0`, and the prover controls h2.
3. This is exactly why rtx1_06 REJECTS but rtx1_05 ACCEPTS: in 06 the honest proof's transcript was
   built with fee=0, so calling verify with fee=50 changes the recomputed seed ⇒ mismatch ⇒ reject.
   In 05 the forge builds the whole proof *consistently* with fee=50 — the only "lie" is the dropped
   carry, which no check re-derives.

**So the f3 monomial/M-SIS question is moot for this attack.** This is NOT a 2^-8 grind on the
monomial opening; it is a **structural soundness hole in the balance relation**: the verifier trusts
the prover's `h2` as the sole carrier of the value-conservation constraint and never recomputes the
required carry `delta = sum_in − sum_out − public_fee` from the committed/recovered amounts and the
public fee. A prover who can emit a structurally-valid proof with `h2` missing the carry inflates at
will. e2/c5 assumed "the UNCONDITIONAL pre/post-h2 binding digests pin the relation value
pre-challenge" — **empirically they pin the FORGED value to itself, not to the true (amounts,fee)
balance.**

## SEVERITY — CRITICAL (calibrated)
- **Class: consensus shielded INFLATION / value-forgery.** A crafted SMILE2 CT proof makes
  `VerifyCT` accept `value_balance`/`public_fee` larger than the spent notes' true surplus ⇒ mint
  transparent BTX from nothing on unshield (z→t), or over-credit on any V2_SEND.
- **Deterministic, work factor 1** (not a probabilistic grind). No M-SIS break, no challenge grind —
  the verifier simply omits an independent balance recomputation.
- **Permissionless at consensus level** (per x2): full `CShieldedProofCheck`/`VerifyCT` runs at
  MEMPOOL admission, so an attacker hand-builds + broadcasts a raw unshield tx — the wallet gate is
  irrelevant. The honest wallet prover refuses (ct_proof.cpp:2254), but an attacker patches their own
  prover (exactly the `g_forge_skip_balance`/`g_forge_zero_carry` two-line change demonstrated here).
- **Caveat on end-to-end realization (why I still flag CRIT, not "needs more"):** this harness proves
  the *primitive* `VerifyCT` accepts the forged CT proof. The full tx path adds outer checks (per
  c5/x2: `CheckTxInputs` value_balance fold, turnstile pool≥0, MoneyRange on value_balance, whole-tx
  statement-digest binding). Those bound *realized transparent egress* to ≤ pool and ≤ MAX_MONEY, but
  they do **not** re-derive shielded balance — they trust the CT proof for that. The CT proof is the
  component that certifies "the shielded side conserves value." With it forgeable, the attacker
  declares `value_balance = (true_surplus + Δ)` and the outer fold happily credits Δ transparent sat
  as long as the running pool covers it (drained from honest depositors). ⇒ a self-funded-looking but
  actually-inflationary unshield. **The decisive empirical next step (gates the CRIT→confirmed-exploit)
  is to submit a forged raw unshield tx through MemPoolAccept/ConnectBlock end-to-end** (now unblocked
  by i3); I assess it succeeds because no outer check recomputes shielded balance, but I did not run
  the full-node submission in this session — flagging that as the one remaining empirical step, with
  the verifier-level break DEFINITIVELY shown.

## IMPACT ON DECISIONS
- **f3 is no longer "candidate-CRIT pending external audit on the monomial reduction."** The active
  shielded value-soundness is **empirically broken at the verifier** via a structural balance hole
  that is independent of the C-002 monomial question. This is strictly worse than the f3 framing:
  it needs no cryptographic break.
- **GATES the self-service unshield feature (v1/x2/x3): DO NOT SHIP.** Self-service unshield turns
  this into a permissionless, operator-free, high-volume inflation surface (the v1/x2 warning, now
  with an empirical accept, not a hypothesis).
- **Raises f3 audit priority to top.** The fix is NOT (only) the monomial swap i5 analyzed — it is
  to make `VerifyCT` **recompute the balance carry from the recovered committed amounts + public_fee
  and require `proof.h2` to equal `g0 + live_y_sum + carry(sum_in − sum_out − public_fee)`** (i.e. add
  an independent value-conservation equation the prover cannot satisfy with a dropped carry), or bind
  the carry term into a digest over the RECOVERED amounts rather than the prover's h2. This is a
  consensus change; needs the external cryptographer (ties to C-002 / i5).

## Vectors attempted (summary)
- rtx1_05 FORGE unbalanced fee=50, zero carry: **RESULT ACCEPTED** — VerifyCT=1 (CRITICAL).
- rtx1_08 FORGE + omega/framework_omega zeroed: **RESULT ACCEPTED** — VerifyCT=1 (gates irrelevant).
- rtx1_10 forge-hooks balanced control: ACCEPTED=1 (expected; honest proofs unaffected).
- rtx1_06 prove fee=0 / verify fee=50 (no hooks): REJECTED=0 (fee is FS-bound; naive lie caught).
- rtx1_01 naive fee-bump 0→1e6: REJECTED=0. rtx1_03 reclaim 50→100: REJECTED=0.
- rtx1_02b omega zeroed on honest proof: REJECTED=0.
- rtx1_09 FORGE + all seeds zeroed: REJECTED=0 (seed tampering breaks transcript binding — not a
  defense vs the self-consistent forge).
- Fee-lie variations confirmed: the magnitude is unconstrained (rtx1_05 fee=50, x1b harness extends
  to fee=150 on in=out=200) — any `public_fee > true_surplus` accepts as long as the carry is dropped.

## Refuting the prior under-calls
- e2 (LOW, "256 monomial governs only commitment-opening binding; relation pinned to negligible by
  the UNCONDITIONAL pre/post-h2 binding digests") — **the digest-pinning premise is empirically
  false for balance**: the digests pin the prover's forged h2 to itself. e2's grind=0/100 only hit
  the prover-refusal path (no forge prover), exactly the gap x1/x1b/x1c filled.
- c5 ("value conservation present & by-construction-correct: smile2 VerifyCT balance") — the
  *outer* fold is present, but the *inner* CT balance relation it relies on is forgeable.
- x1b code-level CRIT — **CONFIRMED by real verifier output.**

## Safety / cleanup
Reused authorized rt asset `rtx1-tests:latest` (an rt* image; not pf3-*/bft-*/evx*/btxn*/other-rt*).
New work in `rtX1C-*` containers (`rtX1C-probe`, `rtX1C-probe2`, `rtX1C-trace`, `rtX1C-rest` — all
`--rm` auto-removed; `rtX1C-grind` stopped+removed) + `/tmp/rtX1C`. Stopped the redundant slow
`rtx1-run` grind container (kept the `rtx1-tests:latest` image).
No production assets touched (no btxd.service / .btx / .local/bin); no pf3-*/bft-*/evx*/btxn*/other
rt* containers or images modified. No git commit. No fabricated results — every `verify=N` above is
copied from real `test_btx` stdout.
