# C-15 Wave 1 — Why standard reductions FAIL for BTX MatExpand (as designed)

*Date: 2026-07-19. Branch context: `feat/bmx4c-exact-accel-lanes`.*  
*Status: **NEGATIVE RESULTS / OBSTRUCTIONS** — informal but precise. Not a security proof.*  
*Companions: `doc/btx-matmul-v4.4-lt-external-c15-packet.md` §0.1,
`doc/btx-matmul-v4.4-lt-c15-prereview-synthesis-2026-07-19.md`,
`/tmp/c15_audit_prior_art.md`.*

> **Hard non-claims.** This note does **not** close LT-C15. It does **not**
> authorize raising `nMatMulDRLTHeight`. It does **not** assert that MatExpand
> is secure or insecure. It only records why several *tempting* reduction
> templates from the literature **do not apply** to the present design, so
> reviewers do not mistake a citation for a proof.

---

## 0. What a “standard reduction” would need to deliver

The falsifiable C-15 game (packet §0.1) asks for absence of an adversary that
outputs an accepting Phase-A digest / Freivalds transcript with advantage
`Adv ≥ ε` over Freivalds false-accept while spending

\[
\mathrm{Cost}(A) \le (1-\delta)\cdot\mathrm{HonestMAC}(n)
\]

(exact-int MAC count; review defaults `δ=1/2`, `ε=2^{-40}`).

A *reduction* would map any such work-skipping adversary to a break of a named
assumption (PRF, secret low-rank hardness, Freivalds, fine-grained OV/SETH,
…). The five sections below show why the usual maps **miss a hypothesis** of
the cited theorem, or prove the **wrong predicate** (correctness ≠ work).

---

## 1. Komargodski–Weinstein (cuPOW): secret low-rank is essential

### 1.1 What KW / Pearl actually price

Komargodski–Schen–Weinstein (ePrint 2025/685; arXiv:2504.09971) and Pearl’s
NoisyGEMM instantiation harden *useful* MatMul by:

1. Letting the miner work on matrices that may be structured, then
2. Forcing a **block transcript** (or equivalent unpredictable commitment) so
   that a **secret / unpredictable low-rank correction** (noise peel) cannot be
   cheaply reconstructed without essentially doing the priced work.

The hardness conjecture is of the form: *batch low-rank random linear
equations* (or transcript unpredictability) — i.e. recovering or bypassing a
**hidden** low-rank object that the verifier’s Fiat–Shamir / RO transcript
binds. The secretness of that low-rank component is load-bearing: if the
adversary already knows the low-rank factors, the “correction identity”
shortcut `(A+E)(B+F) = AB + AF + EB + EF` becomes ordinary algebra, not a
hardness assumption.

### 1.2 What BTX MatExpand actually exposes

Normative MatExpand (v4.4-LT):

```
Y  = G · W          # panels from header / template / nonce seeds
B32 = Y · H         # ⇒ rank(B32) ≤ w = 128  (public structure)
prf_key = SHA256("BTX_MATEXPAND_PRF_V44LT" ‖ seed_W)
B̂[i,j] = Extract(B32[i,j], i, j, prf_key)
```

| Object | KW / Pearl | BTX MatExpand |
|---|---|---|
| Operand matrices | Often external / job inputs | **Deterministic** from public seeds |
| Low-rank object | **Secret** noise / correction (priced to hide) | **Public** thin factorization `G,W,H` (priced to *compute*) |
| `rank ≤ r` | Adversarial shortcut if peelable | **By design** (`w=128`); honest cost is `Θ(n²w)`, not `Θ(n³)` |
| Binding mechanism | Transcript RO over tiles | Sketch digest + Freivalds on `Ĉ`; Extract on cells |

Anyone who knows the header / nonce / template can **locally regenerate**
`G,W,H` and therefore `B32`. There is no hidden low-rank secret whose
recovery is the hardness statement.

### 1.3 Spell the missing secret

**Missing KW hypothesis (the secret that is not present):**

> A low-rank matrix (or low-rank noise / correction factors) that is
> **information-theoretically or computationally hidden** from the miner /
> adversary at the time work is claimed — bound only through a transcript or
> commitment that does not reveal the factors — such that bypassing MatMul
> reduces to solving a batch of random low-rank linear equations in that
> secret.

In BTX:

- `G, W, H` are **public deterministic functions of seeds**.
- `B32 = (G·W)·H` is **deterministically regenerable**; `rank(B32)≤128` is
  public knowledge, not a secret.
- Extract’s `prf_key` is likewise `SHA256(tag‖seed_W)` — **public given the
  same seeds** (it is a domain-separated mixer key, not a KW-style hidden
  noise).

Therefore: **KW-style reductions that start from “adversary that skips work
given only a transcript of a product with secret low-rank noise” do not
instantiate.** Citing cuPOW / Pearl as a MatExpand work lower bound is a
category error: same *meta-class* of “don’t let low-rank algebra skip MatMul,”
different *hypothesis* (secret peel vs public thin Expand + nonlinear Extract).

**What BTX *does* price instead:** exact GEMMs on the thin panels, then
cellwise nonlinear Extract so that Freivalds-linear probes on `B̂` cannot
reassociate through `G,W,H`. That is an **Extract–Freivalds composition
conjecture**, not KW’s secret-low-rank conjecture. Sufficiency remains open
(packet C15-A/B; synthesis: linear class witnesses PASS, unrestricted class
INCONCLUSIVE).

---

## 2. “ChaCha20 is a PRF ⇒ no `(1−δ)·HonestMAC` adversary” is a non-sequitur

### 2.1 What a PRF assumption actually gives

If the ChaCha20 block function is a secure PRF on distinct
`(key, nonce, counter)` tuples, then MANT/SCLE keystreams used by
`ExtractDequantMatExpand` are indistinguishable from uniform **as bitstrings
keyed by `prf_key`**. Precedent for *that* claim shape: AEAD analyses
(Procter ePrint 2014/613) under nonce-respecting ChaCha-PRF.

That yields at most:

- Extract is not an efficient **affine** function of `B32` in the ideal-PRF
  model (aligns with in-tree `matexpand_not_affine_in_raw` as a *witness*, not
  a proof of the C-15 game);
- related-key / weak-nonce misuse must be argued separately for BTX’s custom
  packing `(raw⊕lane, pack(i,j), remix)`.

It does **not** quantify exact-int MAC cost of producing an accepting
`Ĥ(σ‖Ĉ)` / Freivalds transcript.

### 2.2 Counterexample template (PRF as thin wrapper around a low-rank core)

Abstract game-breaking template (not claimed to match BTX consensus Extract —
a **reduction-failure** template):

1. Let `Core(seed)` be a **cheap low-rank** object, e.g. `B32 = (G·W)·H` with
   `w ≪ n`, regenerable in `O(n²w)` or less via panel reuse / affine fold.
2. Let `Wrapper(B32[i,j], i, j, K) = PRF_K(…)` be a secure PRF applied
   **entrywise** (or as a thin post-process) whose outputs feed a verifier that
   only checks a **linear** predicate in the wrapped matrix (Freivalds /
   sketch).
3. If there exists a surrogate `f` (affine / low-degree / homomorphism) such
   that Freivalds probes on `Wrapper∘Core` rewrite as probes on `G,W,H` alone,
   then an adversary can accept with non-negligible advantage while paying
   ≪ dense `n×n` work — **even if Wrapper is an ideal PRF**.

The PRF can be perfect and the PoW still collapses, because hardness was never
“distinguish keystream from random”; it was “you must materialize a dense
nonlinear image before linear verify.” Packet §0.1 already states this
explicitly:

> ChaCha20 being a PRF does not imply a MatExpand work lower bound.

**Logical form of the fallacy:**

```
PRF-security(ChaCha)  ⇏  ∀A: Cost(A) > (1−δ)·HonestMAC  ∨  Adv(A) < ε
```

The missing bridge is a **no-shortcut / work-binding** statement about
`Extract ∘ MatExpand` under Freivalds-linear probes (novel relative to AEAD
proofs). Without that bridge, “ChaCha looks fine” is necessary hygiene, not a
C-15 PASS.

---

## 3. Freivalds soundness alone does not give a work lower bound

### 3.1 What Freivalds proves

For random challenges and `R` rounds over field size `q`, Freivalds gives

\[
\Pr[\text{false accept of } \hat C \ne U\hat A\hat B V] \le O(q^{-R})
\]

(BTX mainnet pin `R=3`, `q=2^{61}-1` → astronomically small false-accept). That
is a **correctness / integrity** guarantee for the committed sketch object.

### 3.2 What it does not prove

Soundness says: *if* the verifier accepts, *then* (whp) the algebraic relation
holds. It says nothing about:

- how many MACs the **prover/miner** spent to produce a true `Ĉ`;
- whether an alternate algorithm (Strassen, panel fold, TMTO, precomputation)
  produced the same `Ĉ` cheaper;
- whether the miner skipped MatExpand and still hit a digest lottery.

Classic PoUW pitfall (Pearl blog; Thaler notes; BTX prior-art panel):
**verifiable MatMul ≠ priced MatMul.** A dishonest worker can be caught by
Freivalds yet an honest-looking cheap path can still mint valid blocks if the
puzzle only checks the relation.

### 3.3 BTX’s intended separation (still not a reduction)

BTX already separates:

| Predicate | Mechanism | Bound type |
|---|---|---|
| Sketch correctness | Freivalds / exact recompute | Soundness ε |
| Lottery binding | `H(σ‖Ĉ)` / seal commit | Collision / preimage |
| Priced work | Marginal MatExpand-B + `B̂·V` + combine | **Conjectural** no-shortcut |

Freivalds closes the first row. C-15 is about the third. **No amount of
increasing `R` turns Freivalds into a MAC lower bound.**

---

## 4. Strassen / Winograd over ℤ / 𝔽_q: consensus binding vs ASERT

### 4.1 Why faster exact MatMul does **not** break consensus binding

Consensus commits to **integer / field values** of sketches and digests, not to
a particular multiplication algorithm:

- If two algorithms compute the **same** bilinear product over `ℤ` or `𝔽_q`,
  they produce identical `Ĉ` bytes and identical digests.
- Strassen, Winograd, Karatsuba-9, adaptive-limb combine, deferred `__int128`
  reduction, ExactGemm on GPU IMMA/MFMA — all are **miner-local efficiency**
  as long as the integer transcript matches (tournament doc;
  `matexpand_batch_algebra_*` / combine identity tests).

A faster exact algorithm is therefore **not a forgery**: it does not create
accepting digests for wrong matrices; it only reduces wall-time / MAC count
relative to schoolbook. Packet / leap-checklist already **retired** the
posture “no cheaper exact mathematical path.”

### 4.2 Why it **does** affect ASERT calibration

ASERT / difficulty must track **honest marginal cost** of the fastest known
*exact* path, not a pedagogical GEMM count:

- If Strassen/Winograd (or FMM) yields a constant-factor or
  \(n^{\omega}\) edge on priced stages (`B̂·V`, combine, or ExactGemm panels),
  measured nonce/s rises.
- Calibrating ASERT to schoolbook `HonestMAC` while miners use Strassen
  **underprices** difficulty (efficiency skew), without opening a Freivalds
  forgery.

| Effect | Consensus binding | Difficulty / ASERT |
|---|---|---|
| Wrong `Ĉ` / forged sketch | Broken (Freivalds / digest fail) | N/A |
| Same `Ĉ`, fewer MACs (Strassen et al.) | **Intact** | **Must recalibrate** to fastest known exact |
| Approximate / floating surrogate | Worthless under exact `𝔽_q` | Not a valid miner path |

So: Strassen-class algorithms are an **efficiency / calibration** concern for
operators and for the C-15 cost model’s secondary wall-time metric — not a
binding break and not a substitute for Extract non-collapse.

---

## 5. What design change would be required to even *attempt* a KW-style reduction

### 5.1 Minimal KW-shaped ingredients BTX lacks today

To even *state* a KW-style theorem about MatExpand-priced work, the protocol
would need something like:

1. **Secret low-rank (or secret noise) object** not regenerable from public
   header seeds alone — e.g. external job matrices with hidden structure, or
   verifier-sampled noise revealed only via transcript commitments;
2. **Transcript / RO binding** over intermediate tiles so that peeling the
   secret reduces to the KW algebraic conjecture (batch low-rank equations);
3. A proof that skipping MatExpand implies solving that conjecture,
   **independent of** Extract’s PRF wrapper.

### 5.2 Concrete design forks (illustrative, not proposals)

| Fork | Idea | Why it may be undesirable for BTX PoW |
|---|---|---|
| **A. Pearl-like noise + transcript** | Add secret low-rank noise; hash block MatMul transcript | Moves BTX toward external-utility PoUW; large wire/verify surface; abandons seed-only determinism that makes light validation and ExactGemm replicas simple |
| **B. Hide panels** | Keep `G,W,H` secret from miners until after commit | Breaks “anyone can regenerate operands from header” — hurts auditability, AccelReplica bit-exact twins, and the AI-native “same op as training GEMM” story with public seeds |
| **C. ZK / PCS matmul** | Replace Freivalds sketches with succinct proofs | Different assumption surface (SRS/FRI); not KW; heavy verify; orthogonal to MatExpand Extract |
| **D. Keep public Expand; prove Extract work-binding** | Stay on current design; name an explicit no-shortcut game | **What packet §0.1 already does** — but this is *not* a KW reduction; it is a novel conjecture |

### 5.3 Why “just add secret low-rank” fights BTX’s PoW goals

BTX v4.4-LT deliberately:

- uses **deterministic seed → panels** so every node / accelerator reproduces
  the same ExactGemm operands;
- prices a **public** thin factorization (`w=128`) as the MatExpand floor;
- relies on **nonlinear position-salted Extract** to kill Freivalds
  reassociation through that public structure.

Importing KW’s *secret* low-rank hypothesis would undo the seed-determinism
and replica story that ExactGemm lanes (CUDA/HIP/CPU) depend on, and would
rebrand the chain toward Pearl-style PoUW with a usefulness/DA layer BTX has
explicitly scoped as v2-elsewhere. That may be a future product fork; it is
**not** a drop-in lemma for today’s MatExpand.

---

## 6. Bottom line for reviewers (still OPEN)

| Tempting citation | Missing hypothesis / wrong predicate | Status for LT-C15 |
|---|---|---|
| Komargodski–Weinstein / Pearl | **Secret** low-rank / transcript peel | **Does not apply** as written |
| ChaCha20 PRF (AEAD-style) | Work-binding bridge past Extract | **Non-sequitur** alone |
| Freivalds soundness | MAC / wall-time lower bound | **Wrong predicate** |
| Strassen / Winograd exact | Forgery / binding break | **Efficiency only** (ASERT) |
| “KW after small design tweak” | Secretness + transcript; conflicts with public Expand | **Possible other protocol**, not current BTX |

**Residual hardness claim (unchanged, unproven):** no efficient adversary wins
packet §0.1 against normative ChaCha20-PRF+M11 Extract. That claim is a
**novel Extract–Freivalds no-shortcut conjecture**, not a corollary of KW,
PRF, or Freivalds.

*Do not claim C-15 cryptographically closed. Public activation remains inert
(`nMatMulDRLTHeight = INT32_MAX`).*

---

## 7. Cross-links

- Game: `doc/btx-matmul-v4.4-lt-external-c15-packet.md` §0.1  
- Synthesis: `doc/btx-matmul-v4.4-lt-c15-prereview-synthesis-2026-07-19.md`  
- Combine / ASERT: `doc/btx-matmul-v4.4-combine-algorithm-tournament.md`  
- Prior-art map: `/tmp/c15_audit_prior_art.md`  
- KW paper: https://eprint.iacr.org/2025/685 — https://arxiv.org/abs/2504.09971  
