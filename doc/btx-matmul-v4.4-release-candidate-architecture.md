> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul v4.4 RELEASE CANDIDATE — ENC-SC Integrated Architecture + Migration Plan

*Status: v4.4 RELEASE-CANDIDATE architecture memo. Integrates the ENC-SC
committed object (doc/btx-matmul-deterministic-nextgen-design.md §7, "the
design memo") into the current undeployed v4 branch as a SINGLE flag-day
upgrade. Supersedes, at the code-plan level, the Stage-2 segregated-proof
carriage (btx-matmul-v4.2-solver-evolution-design.md §3,
btx-matmul-v4.2-relay-hardening-design.md) and the ENC-BMX4C-D profile.
BLOCKING DEPENDENCY: the ENC-SC soundness review (round-by-round-soundness
writeup + Circle-FRI-over-M61 cryptanalysis) is under SEPARATE adversarial
analysis; nothing here activates before it passes (§4.5). Written 2026-07-18.*

---

## 0. Framing: why this is one flag day, not a migration

Nothing in this branch is live. Mainnet has `nMatMulV4Height = INT32_MAX`
(src/kernel/chainparams.cpp:757), and the branch already asserts that v4 and
ENC-BMX4C activate at the SAME height (`nMatMulV4Height ==
nMatMulBMX4CHeight`, chainparams.cpp:158-167) — i.e. ENC-S8 was never going
to be live on any production network, and ENC-BMX4C-D is parked behind
`nMatMulBMX4CDHeight = INT32_MAX` plus the fail-closed
`BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY{false}` flag
(src/consensus/params.h:225). There is no deployed history to migrate, no
dual-profile window to manage, and no reason to preserve activation ladders
that exist only to sequence upgrades on a live chain.

Therefore the v4.4 release candidate is defined as: **at the single height
`nMatMulV4Height`, the live committed object IS ENC-SC** — the BMX4-C
operand encoding and GEMM pipeline unchanged, the flat 8 MiB relayed sketch
replaced by the canonical LDE Merkle commitment `R_LDE` in the digest
preimage plus a ≤ 256 KB in-block sum-check + Circle-FRI proof (design memo
§7.1-§7.3). The entire segregated-proof subsystem (store, relay, chunking,
pending-queue) is deleted from the tree, not height-gated off: at no height
on any network does any of it ever execute.

This is a v5-class L0 amendment shipped under the v4.4 release train; §4.5
states the constitutional position precisely.

---

## 1. Profile model

### 1.1 Decision: REPLACE, do not add a fourth ladder rung

**Recommendation: ENC-SC replaces ENC-BMX4C/-D as the sole activatable
profile at `nMatMulV4Height`. Do not add ENC-SC as a fourth rung above the
existing ladder.** Justification:

1. **The ladder encodes deployment history that never happened.** The
   S8 → BMX4C → BMX4CD sequencing (params.h:416-461,
   `GetMatMulEncodingProfile` :790-795) exists to stage upgrades over a live
   chain. With all heights INT32_MAX everywhere except regtest, keeping three
   dead rungs under a fourth live one means four verify paths, four
   golden-vector families, and three sets of activation asserts that are pure
   audit surface with zero function. The design memo's own migration sketch
   (§7.7-1) assumed a live chain; the RC context is strictly simpler.
2. **ENC-BMX4C-D is obsoleted by construction.** D existed to raise enforced
   per-nonce tensor work by growing m at a 4× storage price, gated on the
   Stage-2 segregated relay. Under ENC-SC, m is a storage-free knob
   (design memo §7.4): retargeting m is a parameter change (+~10-20 KB of
   proof per doubling), not a new profile with a new carriage. D, its
   segregated carriage, and its entire relay stack are deleted (§2.3).
3. **One profile = one flag day = one adversarial review scope.** The
   external soundness review (separate analysis) reviews exactly the object
   that ships. A branch where ENC-BMX4C could also be activated is a branch
   where the review scope is ambiguous.
4. **Profile-ID hygiene is preserved.** "Profile IDs are never reused or
   redefined once activated on any network" (params.h:94) — regtest has
   activated 1-3, so the enum values 1-3 stay RESERVED (retained in the enum
   as documented historical constants, activation paths removed); ENC-SC
   takes a fresh ID = 4.

What ENC-SC keeps from ENC-BMX4C (deliberately): the M11+E8M0 operand
encoding, all BMX4C_* magnitude/limb constants (params.h:132-142), the
b = 4 / m = 1024 production shape (`BMX4C_SKETCH_RANK_M`, :154), the C-1'
accumulator-eligibility anchors (:162-166), seeds/σ/I1' nonce rules, and the
GEMM + C-13' limb-combine pipeline. ENC-SC changes only what happens AFTER
`ComputeSketchOptimal` produces Ĉ: commitment, carriage, and verification.

### 1.2 New profile definition (src/consensus/params.h)

```cpp
enum class MatMulEncodingProfile : uint8_t {
    ENC_S8     = 1,  // RESERVED (regtest-historical; no activation path in v4.4)
    ENC_BMX4C  = 2,  // RESERVED (regtest-historical; encoding constants live on inside ENC_SC)
    ENC_BMX4CD = 3,  // RESERVED (never activated on any public network; deleted outright)
    //! v4.4 ENC-SC (nextgen design §7): BMX4-C operand encoding + b=4/m=1024
    //! shape UNCHANGED; committed object = canonical Merkle root R_LDE of the
    //! rate-rho circle-domain LDE of C_hat; matmul_digest = H(sigma||R_LDE);
    //! relayed object = in-block sum-check + Circle-FRI proof, hard cap 256 KB.
    ENC_SC     = 4,
};

enum class MatMulCommitmentScheme : uint8_t {
    FLAT_SKETCH  = 1,  // legacy 8*m^2-byte sketch, digest H(sigma||C_hat) — regtest vector replay only
    LDE_SUMCHECK = 2,  // ENC-SC: H(sigma||R_LDE) + in-block sum-check/Circle-FRI proof
};

struct MatMulProfileParams {
    MatMulEncodingProfile  profile;        // ENC_SC
    MatMulCommitmentScheme commitment;     // LDE_SUMCHECK
    uint32_t tile_b;                       // 4  (unchanged)
    uint32_t sketch_rank_m;                // 1024 (unchanged; N = m^2 = 2^20)
    uint32_t fri_rate_log2;                // 1  => rho = 1/2, codeword 2^21 (silicon-tunable pre-activation; rho=1/4 is the hash-vs-size knob)
    uint32_t fri_queries;                  // 80 (proven Johnson-bound regime; do NOT price the up-to-capacity conjecture)
    uint32_t fri_fold_arity_log2;          // 2  => arity-4 folding, ~8 layers at 2^21
    uint32_t grind_bits;                   // 20 (proof-of-work grind on the FS transcript)
    uint64_t proof_size_cap;               // 256 * 1024 bytes, HARD consensus cap on the in-block proof
    // RETIRED: sketch_payload_bytes (no flat sketch is ever relayed),
    // RETIRED: proof_segregated    (nothing is ever segregated).
};
```

These are compile-time PROFILE DEFINITIONS in the sense of params.h:129-131:
changing any of them (rate, queries, arity, grind, cap, leaf format, domain
order) defines a different profile → new hard fork + regenerated golden
vectors. They are surfaced through `MatMulProfileParams` (rather than only as
`constexpr`s) so every call site — verify dispatch, payload cap, miner,
bench — reads one struct, per the existing design §4.2 discipline. Alongside
them, a new pinned constants block (`SC_LEAF_BYTES{512}`,
`SC_DOMAIN_LOG2{21}` at rho=1/2, `SC_MERKLE_DOMAIN_TAGS`,
`SC_FS_DOMAIN_TAGS`, F_{q²} irreducible polynomial, canonical
coset/ordering constants) mirrors the BMX4C_* block at params.h:125-166.

`GetMatMulEncodingProfile(height)` collapses to: v4 active ⇒ `ENC_SC`
(production networks); the regtest-only legacy replay path keeps
FLAT_SKETCH selectable behind a regtest-keyed option for differential
testing (§5), never on public networks. Consequently in `Consensus::Params`:

- **DELETE** `nMatMulBMX4CHeight` + `nMatMulBMX4CAsertRescale{Num,Den}`
  (:429-440) — folded into `nMatMulV4Height` (chainparams already forces
  equality; make the code say what the asserts were enforcing).
- **DELETE** `nMatMulBMX4CDHeight` + `nMatMulBMX4CDAsertRescale{Num,Den}`
  (:461-469) and `IsBMX4CDActive`.
- **KEEP** `nMatMulV4Height`, `nMatMulV4Dimension` (+min/max),
  `nMatMulV4AsertRescale{Num,Den}` (:401-402, now calibrated for the ENC-SC
  work unit, §4.4), the verify budgets (:409-410; re-tuned — the ENC-SC
  cascade is fail-fast, §4.2), and the header-PoW throttle (:470-489,
  unchanged and still wanted: matmul_digest remains a self-declared field).
- **DELETE** `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY` (:225) — replaced by
  the ratification gate, §4.1.
- `nMatMulV4FreivaldsRounds` (:384): retained for the regtest legacy replay
  path only; documented as inert at ENC_SC heights (the SC verifier has no
  Freivalds rounds — its parameters are the fri_* fields).

---

## 2. Code map

### 2.1 ADD

| File | Contents |
|---|---|
| `src/matmul/matmul_v4_sc.h/.cpp` | The consensus-normative ENC-SC reference (CPU, pure integer, the analogue of `matmul_v4::VerifySketch` being "the consensus definition"). Contents: (i) **F_{q²} arithmetic** (q = 2⁶¹−1, q ≡ 3 mod 4 ⇒ F_q[i]/(i²+1); canonical reduced representation pinned); (ii) **circle domain** over x²+y²=1 (order q+1 = 2⁶¹ exactly), pinned generator, coset, and index ordering; (iii) **circle-FFT / LDE**, every butterfly exact mod-q — no floats, no approximate NTT; (iv) **canonical Merkle tree**: 512-B leaves in pinned tile order, domain-separated SHA-256d, NO salts / blinding / prover choices (the I-F canonicity rule as normative code); (v) **Fiat–Shamir transcript** (all challenges from `H(σ‖R_LDE‖…)`, schedule pinned; reuses `src/matmul/transcript.*` hashing conventions); (vi) `ComputeCommitmentSC(sketch) → R_LDE` — the per-nonce miner path; (vii) `ProveSC(header, sketch) → proof bytes` — winner-only: DEEP quotients, FRI folding, ~80 query openings with deduplicated paths, sum-check prover with the two O(n²)+O(nm) end-vector computations; (viii) `VerifySketchSC(block, dim, profile, proof, digest_out)` — the §7.3 cascade (§2.2 below); (ix) canonical proof (de)serialization + malleability rejection (any non-minimal encoding, duplicated path node, or trailing byte ⇒ invalid). |
| `src/matmul/matmul_v4_sc_batch.h/.cpp` | Cross-nonce batched commit, mirroring `BatchedSketchMiner` (matmul_v4_batch.h): per nonce, GEMM output Ĉ → circle-LDE → leaf hash → tree → `H(σ‖R_LDE)` vs target. Invariant (as today, matmul_v4_batch.h:36-40): batched results byte-identical to the single-nonce reference; batching is miner-only. |
| `src/cuda/matmul_v4_sc_accel.cu`, `src/hip/matmul_v4_sc_accel.hip`, `src/metal/matmul_v4_sc_commit_kernels.metal` | Device commit path (per-nonce LDE + Merkle fused after the GEMM), §3. Plugged into the `accel_v4.h` backend contract (matmul_v4::{cuda,hip,metal} namespaces, :205-236). |
| `src/test/matmul_v4_sc_tests.cpp`, `src/test/matmul_v4_sc_adversarial_tests.cpp`, `src/test/data/matmul_v4_sc_vectors.json` | Honest + adversarial golden vectors (§4.3); FS-transcript replay vectors; proof-malleability vectors. |
| `src/bench/` — extend `matmul_v4_stage_bench.cpp` | New stages: per-nonce LDE, per-nonce leaf+tree hashing, winner ProveSC, VerifySketchSC (split by cascade step). This bench is the activation gate instrument for the ×1.4 floor (§4.4). |
| functional tests | `test/functional/feature_matmul_sc.py`: regtest mine/verify/reorg with in-block proofs; proof-cap edge; invalid-proof rejection classes (MUTATED vs consensus-fault). |

### 2.2 CHANGE

- **`src/consensus/params.h`** — as §1.2. Also: the D-profile constants
  `BMX4CD_SKETCH_RANK_M` (:161) and the ENC_BMX4CD enum commentary
  (:104-122) deleted; the Stage-2 coupling comment block (:186-224) deleted
  wholesale, replaced by the §4.1 ratification-gate block.
- **`src/pow.cpp`**
  - `CheckMatMulV4SketchVerifies` (:3543-3618): the dispatch gains its final
    form — at ENC_SC (the only production branch) it runs the §7.3 cascade:
    1. parse `R_LDE` from the proof prefix; `H(σ‖R_LDE) == matmul_digest`;
       target check (2 hashes — instant);
    2. FS transcript replay; FRI folding/query/DEEP verification against
       R_LDE (~2-4×10⁴ hashes, 5-15 ms);
    3. sum-check replay (12 rounds over F_{q²}, µs);
    4. end-point check LAST (DoS fail-fast): XOF-expand B (A/U/V
       template-cached exactly as today), evaluate `P̃(r_a,r_k)`,
       `Q̃(r_k,r_c)` via two O(n²)+O(nm) vec–mat–vec passes over the
       BMX4C-encoded operands, compare to the sum-check's final claim.
    The digest-equality + target lines (:3614-3615) remain the shared tail.
    The BMX4C/BMX4CD/S8 branches survive only under the regtest legacy
    replay gate (or are compiled out of production dispatch entirely — final
    call at implementation review; the memo's default is regtest-gated).
  - `IsMatMulV4PayloadSizeValid` (:3512-3531): `matrix_c_data` now carries
    the word-packed proof; the exact-words backstop becomes
    `ceil(proof_size_cap/4)` = 65,536 words (vs 2·m² today), and the
    byte-exact gate moves into the SC deserializer. Empty `matrix_c_data`
    ⇒ invalid (proofs are mandatory and in-block; there is no INCOMPLETE
    state — §4.2).
  - `CheckMatMulProofOfWork_V4ProductCommitted` (:3620-3649): unchanged in
    shape — in-block carriage is once again the ONLY carriage. Comment
    references to segregated routing deleted.
- **`src/kernel/chainparams.cpp`**: delete the V4==BMX4C mirroring asserts
  (:158-167) and the D-height invariant block (:197+); delete the regtest
  `-regtestbmx4cdheight` plumbing; `AssertBMX4CConstructionInvariants`
  becomes `AssertSCConstructionInvariants` (still pins m·tile_b ==
  production dim, and adds: proof_size_cap sanity, 2·m² LDE domain fits the
  2⁶¹ circle order, leaf geometry divides the codeword).
- **`src/rpc/mining.cpp` `GenerateBlock`**: the winner path calls `ProveSC`
  and packs the proof into `matrix_c_data` (replacing both the flat-sketch
  packing and the `OffloadMatMulV4SegregatedProofToStore` call).
- **`src/validation.cpp` `ContextualCheckBlock`**: single in-block route;
  the segregated routing and the tri-state
  `MatMulSegregatedProofStatus{OK,INCOMPLETE,MUTATED,CONSENSUS_FAIL}`
  handling collapse to the ordinary valid/MUTATED/consensus-fault split the
  in-block path already has. `FlushStateToDisk`'s proof-store `Sync()`
  coupling deleted.
- **`src/primitives/block.h`**: wire-invariant comment: `matrix_c_data` =
  word-packed ENC-SC proof, ≤ proof_size_cap.
- **`src/matmul/matmul_v4_bmx4.*`**: `VerifySketchBMX4D`, `kTileBMX4D`, and
  all D-tagged domain-separation paths deleted; the BMX4C encoding/expand/
  limb-combine code is RETAINED (it feeds ENC-SC's GEMM and the verifier's
  end-point operand expansion).

### 2.3 DELETE at activation (= delete from the tree now; nothing is live)

- **`src/matmul/matmul_proof_store.h/.cpp`** — the entire store: memory/disk
  modes, leveldb backing, archive role, prune window, `Sync()`, the
  process-wide singleton and its free-function wrappers. No consensus path
  may depend on any node-local store: ENC-SC verification is a pure function
  of (header, block body). (If a non-consensus proof-regeneration cache is
  ever wanted for serving deep history, it is new code with no consensus
  edge — explicitly out of scope for the RC.)
- **`src/protocol.h/.cpp`**: `GETMATMULPROOF`/"getmmproof",
  `MATMULPROOF`/"matmulproof", `MATMULPROOFCHUNK`/"mmproofchunk"
  (:300-321, allNetMessageTypes entries :366-367), and the
  `NODE_MATMUL_PROOF_ARCHIVE` service bit.
- **`src/net_processing.cpp`** — the whole Stage 2b/2c/2d complex:
  - constants :118-193: `MATMUL_PROOF_REQUEST_TIMEOUT`, `_RETRY_RESET`,
    `_ARCHIVE_PREFERENCE_GRACE`, `MAX_MATMUL_PROOFS_PENDING{,_BYTES}`,
    `_PENDING_TTL`, `_MAX_ATTEMPTS`, serve token buckets
    (`MATMUL_PROOF_SERVE_BUCKET_MAX/_REFILL/_GLOBAL_BYTES_PER_SEC/
    _DEDUP_WINDOW`);
  - `Peer::m_matmul_serve_tokens` (:566) and the node-wide egress byte
    bucket (:1040-1045);
  - `ServeMatMulProofChunks` (:1052, :2103) and the GETMATMULPROOF /
    MATMULPROOFCHUNK message handlers;
  - `QueuedMatMulProof` (:1183-1224), `m_matmul_proofs_pending` (:1225) +
    `m_matmul_proofs_pending_bytes` (:1228), `ResetMatMulReassembly`
    (:1232, :2033), the eviction sweep (:2073+), the stale-request sweep
    (:1992), the block-download interplay carve-out (:1832-1840), the
    archive-peer preference (:6261) and buried-proof grace (:8146).
- **`src/pow.cpp`**: `GetMatMulProofSizeCap` + `MATMUL_SEGREGATED_PROOF_
  OVERHEAD` (:3651-3655 — the SC cap is a profile field, not derived
  plumbing), `CheckMatMulV4SegregatedProof` (:3657-3713),
  `OffloadMatMulV4SegregatedProofToStore` (:3715+),
  `MatMulSegregatedProofStatus`.
- **assumevalid buried-proof trust** (matmul_proof_store.cpp:139 rationale):
  moot and deleted with the store. Deep-history posture is now strictly
  stronger: proofs beyond burial depth are DROPPED by everyone and remain
  re-derivable from the header forever (design memo §7.5), and any deep
  block is directly re-auditable by digest-only recompute (Candidate A) —
  `assumevalid`-class policy applies only in the same sense as Bitcoin
  script checks, with re-derivability underneath it.
- **Init/args/docs**: the `-matmulproofarchive`-class startup options, the
  archive-node role documentation, and the Stage-2 sections of the relay
  docs (marked superseded, not rewritten).
- Segregated-path tests (proof-store unit tests, relay/chunking functional
  tests, `-regtestbmx4cdheight` tests) — deleted with their subject.

The deletion list is a feature: roughly two thousand lines of relay,
reassembly, serving-limit, persistence, and trust machinery — all of it
consensus-adjacent DoS surface — is replaced by "the proof is in the block."

---

## 3. GPU backends (CUDA / Metal / HIP)

Contract (extends `accel_v4.h`; the batched CPU reference in
`matmul_v4_sc_batch.*` is the structure every backend mirrors, as
matmul_v4_batch.h:15-34 does today):

1. **Per-nonce, fused after the GEMM** (this is the hot path — runs for
   every nonce, ~557k SHA compressions + 4.4×10⁷ mod-q mults per nonce):
   - Ĉ residues (m² = 2²⁰ F_q words, already on device from the batched
     limb-combine GEMM) → **circle-FFT/LDE** to the 2²¹-point rate-1/2
     codeword, exact mod-q integer butterflies (64-bit mulhi or 32-bit limb
     arithmetic; NEVER float/FP-FFT — determinism is consensus);
   - codeword → 512-B leaves in pinned order → **SHA-256d Merkle tree** →
     `R_LDE` (reuse each backend's existing device SHA-256 from the XOF
     operand-expansion kernels);
   - `H(σ‖R_LDE)` vs target on device; only winners come back to host.
   The LDE is ~0.06 % of the GEMM MAC count and integer-ALU work that
   overlaps tensor-core GEMM; the hashing is the real ×~1.42 non-GEMM floor
   (393k → 557k compressions/nonce) and must be pipelined against the next
   nonce's GEMM.
2. **Winner-only ProveSC**: NOT a per-nonce requirement and not an
   eligibility requirement. The CPU reference (~1-3 s) is sufficient at 90 s
   spacing; backends MAY accelerate FRI folding/DEEP on device later. The
   proof bytes must be byte-identical to the reference regardless of where
   they are produced (the transcript is canonical; there is no
   prover-choice slack to differ in).
3. **Determinism requirement — unchanged in kind, extended in scope.** The
   existing rule (backend_capabilities_v4.h: integer-exact s8 tensor path,
   FP accumulate never admissible, cross-backend bit-identity vs the CPU
   reference enforced by `matmul_v4_backend_determinism_tests.cpp` before a
   backend is mining-capable) now covers the commit path too: a backend is
   mining-eligible only if GEMM → LDE → leaves → `R_LDE` is bit-identical to
   `ComputeCommitmentSC` on the cross-vendor golden vectors. Extend
   `Eligibility::self_test_required` and the golden-vector harness
   (§B.6/C-3 machinery) with SC commit vectors; the per-backend
   ok/mismatch/fallback counters in `accel_v4.h` gain `*_commit_*` rows.
   Mismatch ⇒ fall back to CPU commit (mine slower, never mine wrong),
   exactly the existing posture.
4. **Kernels touched**: `src/cuda/matmul_v4_sc_accel.cu` (+ scheduler hooks
   in `src/cuda/cuda_scheduler.*`), `src/hip/matmul_v4_sc_accel.hip`,
   `src/metal/matmul_v4_sc_commit_kernels.metal`; the BMX4 GEMM kernels
   (`matmul_v4_bmx4_accel*`) are unchanged except deletion of D-tile paths.

---

## 4. Activation + safety

### 4.1 Single-height flag day, and what replaces the relay-ready gate

One knob: `nMatMulV4Height`. At that height the network switches v3 → v4.4
ENC-SC in one block: new digest preimage, new in-block proof, new verifier.
INT32_MAX on every public network until ratification. Regtest keeps a low
height for CI.

`BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY` guarded against activating a
profile whose proofs might not be obtainable. That failure mode NO LONGER
EXISTS: the proof is ≤ 256 KB, in the block body, under every message limit
(the BIP324 24-bit packet ceiling that broke Stage 2b is moot), propagates
with the block, and a block without its proof is simply INVALID — there is
no INCOMPLETE state, no fetch, no stall. What replaces the flag, same
fail-closed mechanism, new object of protection:

```cpp
// v4.4 ratification gate. FALSE until (i) the external ENC-SC soundness
// review (RBR-soundness writeup + Circle-FRI-over-M61 cryptanalysis, under
// separate adversarial analysis) has PASSED, (ii) the H100/B200 silicon
// measurement has pinned rho/queries and the ASERT rescale, and (iii) the
// L0-amendment ratification (§4.5) has completed. While false,
// AssertSCConstructionInvariants HARD-BLOCKS any public network from
// configuring a non-INT32_MAX nMatMulV4Height (regtest exempt).
static constexpr bool BTX_MATMUL_ENC_SC_RATIFIED{false};
```

### 4.2 Fail-closed verification posture

- Proof mandatory + in-block ⇒ verification is a pure function of received
  bytes (D1); no store, no peer round-trip, no trust in local state.
- Cascade order is normative and fail-fast (§2.2): garbage costs the
  verifier ~ms of hashing before any O(n²) work — strictly better DoS
  posture than today's always-run XOF+Freivalds, so the per-peer/global
  verify budgets (:409-410) are re-tuned (kept as a backstop, sized to the
  step-4 cost only).
- Malleability: the only mutable bytes are the proof body; a tampered proof
  fails step 1/2 as a body MUTATION (non-permanent, cannot poison the honest
  block — same classification discipline as today's
  `MatMulV4PayloadMatchesCommitment` split, with `H(σ‖R_LDE)` as the binding
  predicate). A proof that reconstructs the digest yet fails the cascade is
  a PERMANENT consensus fault.
- The header-PoW throttle (:470-489) is retained unchanged (matmul_digest is
  still self-declared at header-sync time).

### 4.3 Golden vectors — honest AND adversarial (all consensus-normative)

Honest: full pipeline vectors at regtest and production shapes — operands,
Ĉ, LDE codeword, leaf bytes, R_LDE, σ, digest, complete proof bytes, FS
transcript at every round, accept. Cross-vendor: every backend must
reproduce R_LDE bit-identically (§3.3).

Adversarial (each MUST reject, with the rejecting cascade step pinned):
- **tampered-codeword**: one LDE word altered, tree honestly rebuilt over it
  → FRI proximity/consistency reject (step 2);
- **grind-attempt** (the §2.4-immunity vector, normative regression): one Ĉ
  tile replaced with garbage, LDE + tree recomputed honestly over the
  altered object, proof generated by the honest prover — must reject at
  sum-check/end-point (steps 3-4), demonstrating there is no free-bit
  channel;
- **non-canonical**: residue ≥ q in a leaf; wrong leaf order; non-canonical
  F_{q²} encoding; padded/truncated/trailing-byte proof; duplicated or
  re-ordered query paths; wrong fold arity; over-cap proof; empty proof;
- **transcript**: challenge derived from a mis-ordered FS absorption;
  grind_bits not satisfied;
- legacy wrong-limb / non-canonical-residue vectors retained on the regtest
  replay path.

### 4.4 ASERT one-time rescale

The per-nonce non-GEMM floor rises ×~1.42 (≈393k → ≈557k SHA compressions;
LDE ALU ~0.06 % of W), so attempts/s at the fork drops by a
hardware-dependent factor. Handled by the EXISTING mechanism:
`nMatMulV4AsertRescale{Num,Den}` (:401-402) — next_target = parent_target ×
Num/Den at `nMatMulV4Height`, then ASERT re-anchors. The ratio MUST be
calibrated from measured marginal nonce/s on H100/B200 via the extended
`matmul_v4_stage_bench` (the twice-burned rule: models were wrong twice;
silicon is the gate). The BMX4C and BMX4CD rescale pairs are deleted with
their heights. Fresh networks bootstrapping nBits for the SC work unit leave
1/1.

### 4.5 Constitutional status (L0 / v5)

This RC amends L0: the digest preimage becomes `H(σ‖R_LDE)` and the
SketchFreivalds verifier structure is replaced — by the constitution's own
text (btx-matmul-v4.2-longevity-threat-model.md:351) a different-coin-class
change. The amendment is proposed openly (design memo §2.5, §9-5), with the
flat-data requirement recorded as the new constitutional input. Preserved
from L0 deliberately: q = 2⁶¹−1 (the circle group makes the field survive),
exact-integer committed path ("no rounding" — every butterfly exact mod-q),
σ/nonce-freshness (I-N verbatim), price-independence, the <1 s verify
budget (150-400 ms), and the hardness floor. **Ratification gate
(blocking, per design memo §7.7-5):** (i) external RBR-soundness writeup of
the exact combined protocol; (ii) Circle-FRI-over-M61 parameter
cryptanalysis — both under the separate adversarial soundness analysis this
memo depends on; (iii) H100/B200 measurement; (iv) the L0-amendment
supermajority process. `BTX_MATMUL_ENC_SC_RATIFIED` mechanizes the gate.
Naming: the branch ships as **v4.4-rc** implementing the **v5-class ENC-SC
amendment**; the version number is release-train bookkeeping, the
constitutional status is v5 and is stated as such in every activation
artifact.

---

## 5. Build order and reuse

1. **Spec freeze** (consensus-normative appendix to the v4 spec): circle
   domain + generator + ordering, twiddle conventions, leaf format, Merkle
   domain tags, F_{q²} canonical form, FS absorption schedule, fold
   schedule, query derivation, proof serialization + dedup, cap, the
   canonicity (no-salt) rule, the cascade order, and the ε budget with the
   proven-regime parameter table. Nothing below starts until this is
   reviewable text — it is also the input the external soundness review
   consumes.
2. **CPU reference + golden vectors** (`matmul_v4_sc.*`, tests §2.1):
   implement against the frozen spec; generate honest + adversarial
   vectors; differential-test the honest object against the retained
   Freivalds reference on regtest shapes (both must accept the same Ĉ;
   any divergence is a spec bug found cheap). Fuzz targets: proof
   deserializer, FS transcript replay.
3. **Consensus wiring + deletion** (§2.2 + §2.3 in ONE change series, so
   the tree never has two live carriage paths): params/pow/chainparams/
   validation/mining rewire, segregated subsystem removal, functional
   tests. The branch is now self-consistent and regtest-minable end-to-end.
4. **Backends** (§3): CUDA first (largest fleet), then HIP, then Metal;
   extend the determinism harness and eligibility gates; run
   `matmul_v4_stage_bench` on H100/B200 → pin ρ/queries/grind and the ASERT
   rescale ratio. If measurement shows the ×1.42 floor tipping wall-time
   GEMM share below the datacenter threshold, the knobs are ρ (1/4 ⇒ ×1.9
   hash but ~40 queries / ~80-100 KB proofs) and leaf width — tune BEFORE
   parameter freeze, not after.
5. **Adversarial audit + ratification**: external soundness review (already
   in flight, separate analysis) over the frozen spec + reference; internal
   red-team pass over the adversarial vector classes (§4.3) and the
   net-facing deserializer; then the L0 process; only then does any public
   network get a height and `BTX_MATMUL_ENC_SC_RATIFIED` flip — one
   reviewed release action, mirroring the discipline the old relay-ready
   flag documented.

**Reused from existing scaffolding:** the entire BMX4C encoding/GEMM/
limb-combine stack and its golden vectors (unchanged under ENC-SC); seed/σ/
XOF derivation (`DeriveSigma`/`DeriveOperandSeed`/`DeriveProjectorSeeds`,
untouched); `transcript.*` FS hashing conventions; `BatchedSketchMiner`
structure and its batch==reference test discipline; `accel_v4.h` backend
contract + fallback counters; `backend_capabilities_v4` eligibility +
determinism self-test harness; `matmul_v4_stage_bench`; the header-PoW
gate; the MUTATED/permanent classification discipline and the
`AssertBMX4CConstructionInvariants` startup-loud pattern (renamed). The
Stage-2 store/relay code itself is reused as nothing: its lesson — proofs
whose availability is not structurally guaranteed become a subsystem — is
the reason the RC carries the proof in-block.

---

*Dependencies: ENC-SC soundness review (separate adversarial analysis) —
blocking for §4.5 gates (i)-(ii). Silicon measurement — blocking for gate
(iii) and all fri_*/rescale parameter freezes. This memo pins architecture
and file-level scope only; no consensus constant in §1.2 is final until
both dependencies clear.*
