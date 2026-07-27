// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_ALG_H
#define BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_ALG_H

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_fri.h> // FriNextPow2 / shared numeric caps
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// ALGEBRAIC-HASH batched FRI over Fp3 — the RECURSION-side Merkle substrate
// (Stage-C spec §2, scratchpad/stage-c-buildable-spec.md). Same polynomial
// mathematics as the batched FRI in matmul_v4_rc_fri_ext3.{h,cpp} (LDE,
// degree-shift RLC, dual-OOD DEEP, v5 half-domain fold, terminal B-constant
// layer, FS replay) with EXACTLY the hash-touching surface swapped:
//
//   Fri3LeafHash / Fri3NodeHash (SHA256d, uint256 digests)
//     → alg_hash::LeafHash / alg_hash::LeafHashRow / alg_hash::Compress
//       (Poseidon2-Goldilocks, digests = 4 Fp lanes) — so every Merkle node
//       is a low-degree algebraic map over GF(p), arithmetizable in V_CS.
//
// APPROACH (spec §2.1 option (b), chosen deliberately): a PARALLEL file. The
// fold/DEEP/NTT helpers of matmul_v4_rc_fri_ext3.cpp live in an anonymous
// namespace (internal linkage), so approach (a) — a MerkleHashPolicy template
// — would have required restructuring the frozen SHA256d consensus file.
// Option (b) keeps matmul_v4_rc_fri_ext3.{h,cpp} byte-for-byte untouched
// (base / non-recursive proofs still use it verbatim); this file re-instates
// the field-arithmetic scaffolding verbatim in its own anonymous namespace and
// swaps only the digest type and the four hash entry points. The spec itself
// recommends (b) for the first cut (isolation; migrate to (a) later).
//
// DIGEST REPRESENTATION: nodes and leaves are std::array<Fp,4>
// (alg_hash::Digest) EVERYWHERE — in the tree, in the proof structs, and in
// the fold-step sibling lists. Conversion to uint256 happens ONLY at the two
// byte boundaries (the SHA256d Fiat–Shamir transcript and proof
// serialization) via the canonical little-endian-limb packing
//   uint256 bytes [8k, 8k+8) = LE64(Canonical(limb_k)),  k = 0..3,
// implemented by Fri3AlgDigestToUint256 / Fri3AlgDigestFromUint256 below.
// Unpacking REJECTS any limb ≥ p, so the packing is a bijection between
// canonical digests and its image (round-trip pinned by unit test).
//
// ROW-WISE BATCH COMMITMENT (spec §2.3, REQUIRED for the recursion cell
// budget): unlike Fri3BatchCommit (one Merkle tree PER column), this path
// commits ONE tree whose leaf i is alg_hash::LeafHashRow over ALL W column
// values at LDE row i (variable-length sponge over 3W+1 Fp lanes). A query
// therefore opens ONE authentication path carrying the whole row, not W
// paths. The RLC composition U, the per-column degree-shift bounds and the
// dual-OOD claims evals_z1/evals_z2 are UNCHANGED — only the Merkle layout
// differs. The SHA base FRI keeps its per-column layout.
//
// FIAT–SHAMIR stays SHA256d-based (spec §2.2): challenge derivation is NOT
// arithmetized in V_CS (the recursive verifier recomputes challenges
// natively), so only the Merkle commitment must be field-native. Distinct
// domain tag ⇒ no transcript collision with the SHA batch path.
//
// ============================================================================
// SOUNDNESS PARAMETERS (recursion path; spec §5.2 — code and statement MUST
// agree). This path ships Q = 192 (NOT the SHA path's 128), g = 40, blowup 16:
//   192·log2(32/17) − 40 = 135.21 bits per proof. Charging a conservative
//   2^28 proof sites for relation shards plus recursive aggregation leaves
//   107.21 bits under the current proximity-term union diagnostic. This is
//   not a complete security theorem; other independently fallible terms must
//   be charged separately.
// The shared cap kRCFriMaxQueriesHard = 128 (matmul_v4_rc_fri.h:82) belongs to
// the SHA paths and is DELIBERATELY not edited; this path carries its own
// kRCFri3AlgNumQueries = 192 and kRCFri3AlgMaxQueriesHard, statically checked
// below. All other numeric parameters (blowup, grinding, fold caps, LDE
// guard) are shared unchanged from matmul_v4_rc_fri.h.
// ============================================================================

namespace matmul::v4::rc {

using gkr_field::Fp;
using gkr_field::Fp3;

/** Field-native Merkle digest: 4 Goldilocks lanes (alg_hash::Digest). */
using Fri3AlgDigest = alg_hash::Digest;

inline constexpr uint32_t kRCFri3AlgBatchProofMagic = 0x33414246u; // 'FBA3'
inline constexpr uint32_t kRCFri3AlgBatchProofVersion = 3;
inline constexpr char kRCFri3AlgBatchDomainTag[] = "BTX_RC_FRIB3ALG_Q192_V3";

/** Lane proof version for the short-transcript Q192 lane. Distinct from 3
 *  (Q192 V3), 5 (dual V5 lane) and 6 (dual Q136 lane); a proof of one version
 *  is rejected by every other lane's verifier at the version check. */
inline constexpr uint32_t kRCFri3AlgShortFsLaneProofVersion = 7;
inline constexpr char kRCFri3AlgShortFsDomainTag[] =
    "BTX_RC_FRIB3ALG_Q192_SHORTFS_V7";

// ===========================================================================
// PR-89 g4 / recommendation #1: Poseidon2 SQUEEZE lane (NOT ACTIVATED).
//
// Short-FS (v7) moved two ABSORBS onto Poseidon2 commitments but left every
// challenge draw as SHA256d(buf || suffix).  That is still a mixed recursive
// verifier: parent in-AIR replay of the seven FRI kinds remains a vertical
// SHA companion.  This lane keeps short-FS absorbs and replaces the squeeze
// with a domain-separated Poseidon2 draw over the same buf-as-Fp-lanes
// encoding, so all eight challenge kinds (airq_lambda via
// aq::AirChallengeDigestP2 + seven FRI kinds here) share one Poseidon2
// proof version and the SHA floor (~57 s producer endpoint) is not load-
// bearing.
//
// Distinct from v3 / v5 / v6 / v7 and from aq::kAirChallengeP2RouteVersion
// (which versions the AIR-quotient digest route, not this FRI proof).
// ===========================================================================
inline constexpr uint32_t kRCFri3AlgP2SqueezeLaneProofVersion = 8;
inline constexpr char kRCFri3AlgP2SqueezeDomainTag[] =
    "BTX_RC_FRIB3ALG_Q192_P2SQZ_V8";
/** Poseidon2 squeeze activation. When true, ActiveConfig selects proof
 *  version 8 (short-FS absorbs + Poseidon2 squeezes) for the live Q192
 *  recursion lane. Joint-flip only with aq::kAirChallengeP2Activated so the
 *  recursive verifier is not permanently mixed SHA/P2. */
inline constexpr bool kRCFri3AlgP2SqueezeActivatedV1 = true;
static_assert(kRCFri3AlgP2SqueezeActivatedV1,
              "PR-89 Poseidon2 FRI-squeeze lane is activated (g4 joint flip)");
static_assert(kRCFri3AlgP2SqueezeLaneProofVersion !=
                      kRCFri3AlgBatchProofVersion &&
                  kRCFri3AlgP2SqueezeLaneProofVersion !=
                      kRCFri3AlgShortFsLaneProofVersion,
              "P2-squeeze proof version must not collide with Q192 SHA lanes");

// ===========================================================================
// PR-89 g4 ACTIVATION.  The short-transcript lane is the lane the Q192
// recursion now PRODUCES and CONSUMES.  Everything the flip changes is derived
// from this ONE constant, so the protocol and every in-AIR / shadow replay of
// it move together or not at all.  There is exactly one place to look to know
// which layout is live.
//
// WHAT THE FLIP DOES NOT DO, recorded here because each is easy to over-read:
//   * The CHALLENGE FUNCTION IS STILL SHA256d.  Fri3AlgFs is a byte-buffer
//     SHA256d transcript and stays one; short-FS replaces two ABSORBED bodies
//     with Poseidon2 commitments -- it does not move the squeeze.  A parent
//     replaying a child challenge in-AIR still replays SHA256d, over 151..591
//     bytes instead of >= 52*W.  That is the whole saving, and it is not the
//     same claim as "the transcript is Poseidon2".
//   * It does NOT change the query-index RULE.  ProtocolChallengeIndex's
//     non-uniform branch is untouched, so every in-AIR index chip and every
//     shadow of that rule stays valid WITHOUT EDIT.  Moving the index rule to
//     the ALGEBRAIC (sigma_core) form is Construction 2, a SEPARATE change.
//   * It does NOT create individual-claim binding.  That is an ORDERING
//     property (roots -> alpha -> z -> claims) and
//     AuditFri3AlgAdaptiveEvaluationOrder still hard-codes
//     legacy_order_individual_eval_binding = false.
// ===========================================================================
inline constexpr bool kRCFri3AlgShortFsActivatedV1 = true;

/** The proof version / domain tag the Q192 recursion lane actually produces.
 *  Every version gate, every shadow parser and every in-AIR transcript model
 *  MUST read these rather than kRCFri3AlgBatchProofVersion, or the parent
 *  computes different challenges than the child and recursion breaks
 *  SILENTLY. */
inline constexpr uint32_t kRCFri3AlgActiveBatchProofVersion =
    kRCFri3AlgP2SqueezeActivatedV1 ? kRCFri3AlgP2SqueezeLaneProofVersion
    : kRCFri3AlgShortFsActivatedV1 ? kRCFri3AlgShortFsLaneProofVersion
                                   : kRCFri3AlgBatchProofVersion;
inline constexpr const char* kRCFri3AlgActiveBatchDomainTag =
    kRCFri3AlgP2SqueezeActivatedV1 ? kRCFri3AlgP2SqueezeDomainTag
    : kRCFri3AlgShortFsActivatedV1 ? kRCFri3AlgShortFsDomainTag
                                   : kRCFri3AlgBatchDomainTag;
/** The two tags have DIFFERENT lengths (23 vs 31) and several transcript
 *  models size their preamble with sizeof(tag)-1.  Reading this instead is
 *  what keeps those models byte-exact across the flip. */
inline constexpr uint32_t kRCFri3AlgActiveBatchDomainTagLen =
    kRCFri3AlgP2SqueezeActivatedV1
        ? static_cast<uint32_t>(sizeof(kRCFri3AlgP2SqueezeDomainTag) - 1)
        : kRCFri3AlgShortFsActivatedV1
              ? static_cast<uint32_t>(sizeof(kRCFri3AlgShortFsDomainTag) - 1)
              : static_cast<uint32_t>(sizeof(kRCFri3AlgBatchDomainTag) - 1);
/** True iff the live Q192 lane absorbs the SHAPE and OOD-EVAL commitments in
 *  place of the 4*W and 48*W verbatim bodies.  P2-squeeze inherits short-FS
 *  absorbs. */
inline constexpr bool kRCFri3AlgActiveShortTranscript =
    kRCFri3AlgP2SqueezeActivatedV1 || kRCFri3AlgShortFsActivatedV1;
/** True iff live challenges are Poseidon2 squeezes (not SHA256d). */
inline constexpr bool kRCFri3AlgActiveP2Squeeze =
    kRCFri3AlgP2SqueezeActivatedV1;

/** Stage-3 recursion query count: Q=192 supports a 2^28-site union budget. */
inline constexpr uint32_t kRCFri3AlgNumQueries = 192;
/** Path-local hard cap (DoS bound for deserialization/verify) — the shared
 *  kRCFriMaxQueriesHard = 128 is a SHA-path cap and stays untouched. */
inline constexpr uint32_t kRCFri3AlgMaxQueriesHard = 256;
/** Per-proof target before the canonical Stage-3 tree union accounting. */
inline constexpr int kRCFri3AlgTargetSoundnessBits = 100;
/** Single-lane Fri3Alg round-by-round / BCS soundness reduction.
 *
 *  PR-89 gate 3 (MACHINE-VERIFIED, no external audit): flipped true once the
 *  executable ledger soundness_scenarios::AssessFri3AlgBcsRbrLedgerV1() machine-
 *  computes AND machine-checks the full single-lane rbr/BCS composition from
 *  THIS backend's construction constants (Q=192, rho=1/16, alpha=17/32,
 *  |Fp3|~2^192): every FIELD round (batching CA, dual-OOD DEEP, DEEP-weight
 *  line-CA, per-fold line-CA) reproduced in the field-bounds-PROVEN [151,168]
 *  window (m_f~154), the BCS state-restoration factor (t*e_rbr + 3(Q^2+1)/2^kappa)
 *  applied, and the composition reproducing the headline 135/128 pair (query
 *  proximity 135 == Fri3AlgSoundnessBoundBits(); shared Poseidon2 collision 128).
 *  Asserted by fra3_bcs_rbr_ledger_* tests.
 *
 *  SCOPE: this asserts ONLY the single-lane rbr/BCS reduction, modulo the
 *  DISCLOSED published proximity-gap (BKS2018/BCIKS2020/Haboeck2022) and
 *  BCS/FS-transform (BCS2016/Block2023) theorem constants recorded as explicit
 *  audit-input assumption lines. It is NOT the global soundness theorem: the
 *  Stage-3 readiness interlock keeps certified_bits at 0 until the remaining
 *  gates (FS-replay, self-similar fixed point, global composition) also close. */
inline constexpr bool kRCFri3AlgFormalSoundnessReady = true;

/** Path-local batch column cap for the RECURSION FRI. The shared
 *  kRCFriBatchMaxColumns = 2^12 is a conservative SHA-path guard; the
 *  recursion's FRI-verifier-as-AIR (V_CS) is a short-and-wide constraint
 *  system whose column count exceeds 2^12 before the self-similar fixed-point
 *  reshaping.
 *
 *  PR-89 rung-4: raised 2^14 -> 2^15 (toy four-slot V_CS ~16996 cols).
 *  PR-89 rung-5: raised 2^15 -> 2^20. With REAL role children (W>>1) the
 *  arity-4 self-similar parent V_CS is 384k-712k COLUMNS (measured:
 *  RunFourSlotRealRoleChildren, recursive_parent_air_tests) — it arithmetizes
 *  four real child constraint systems + their Q=192 FRI verifiers in-AIR. At
 *  2^15 = 32768 the real-child parent could not commit its OWN FRI proof; the
 *  aggregate root was unprovable at real node width. 2^20 = 1048576 admits the
 *  full real width with headroom (712k < 2^20).
 *
 *  SOUNDNESS (verify, do not assume — the prior note here was WRONG for the
 *  shipped path). Two distinct soundness dimensions:
 *   (1) QUERY-PROXIMITY: Fri3AlgSoundnessBoundBits() = Fri3AlgProximityBoundBits()
 *       (= floor(Q·log2(32/17)) = 175, reads ONLY Q) + grind_credit − regrind
 *       = 135 bits. Genuinely W-INDEPENDENT — the column count is never read.
 *       This is the gate-scored quantity (AssessRCStage3RecursiveReadiness) and
 *       raising the cap does not move it.
 *   (2) FIELD / BATCHING-RLC: this term IS W-dependent, contrary to the old
 *       comment. The active recursion config kFri3AlgQ192V3Config holds
 *       independent_batching_coefficients = FALSE (see .cpp:~522) => the shipped
 *       path uses SinglePower [1,λ,λ²,…] geometric batching, whose loss is
 *       batching_loss = log2(W−1) bits (ePrint 2023/1071 Lemma 5.10 (t−1)
 *       factor; matmul_v4_rc_stage3_soundness_scenarios.cpp:~1720). The
 *       (W+2)/|Fp3| ≈ 2^-177 RLC bound applies ONLY to the independent-coeff
 *       path, which is NOT active — so the earlier "W-independent 2^-177"
 *       rationale described a path that is not shipped and MUST NOT be relied on.
 *
 *  Net: the batching cost is only LOGARITHMIC in W. Raising 2^15 -> 2^20 costs
 *  the field term just log2(2^20/2^15) = 5 bits. field_rbr = |Fp3| − 2·lde_log2
 *  − theorem_const(≈17.07) − log2(W−1). MEASURED real parent shape
 *  (RunFourSlotRealRoleChildren, CoupledPermutation): parent_cols=384984,
 *  parent_rows=256 => n_lde = 256·16 = 4096, lde_log2=12, so field_rbr ≈
 *  192 − 24 − 17.07 − 18.55 ≈ 132.4 bits at W=385k (≈130.9 at W=2^20). Even at
 *  the LDE cap kRCFriMaxLdeLog2=24 (worst case): ≈107 bits at W=2^20. All stay
 *  above the 100-bit per-node target AND the ~78.5/67.6-bit composed floors, so
 *  batching never becomes the binding term at real width. => The cap is an
 *  IMPLEMENTATION guard, not a soundness limit; committing 384k-712k columns is
 *  SOUND, with a small bounded logarithmic field-side cost (NOT because the
 *  bound is W-independent).
 *
 *  MECHANICS: no fixed-size array is sized by this constant (verified: no
 *  std::array/C-array of extent kRCFri3AlgBatchMaxColumns exists); every use is
 *  a `> cap` bounds guard or a dynamic allocation LINEAR in W (batch memory,
 *  row-tree leaf width). LDE is per-column, capped by kRCFriMaxLdeLog2=24
 *  independently of W. NOTE: recursive.cpp MAX_VECTOR_ITEMS = this cap also
 *  bounds proof-parse vector lengths, so the untrusted-parse allocation ceiling
 *  scales 32× with this change (still bounded, dynamically sized). Path-local
 *  ONLY: the SHA base path keeps 2^12 untouched. */
inline constexpr uint32_t kRCFri3AlgBatchMaxColumns = 1u << 20;
static_assert(kRCFri3AlgBatchMaxColumns >= kRCFriBatchMaxColumns,
              "recursion cap must admit at least the shared width");
// SinglePower batching loss = log2(W−1) bits (shipped path; independent-coeff
// held FALSE). At W = 2^20 that is 20 bits; field_rbr = |Fp3| − 2·lde −
// theorem_const − 20 stays ≥ ~107 bits even at the lde=24 cap — above the
// 100-bit per-node target. The cost is LOGARITHMIC, so this ceiling is safe.
static_assert(kRCFri3AlgBatchMaxColumns <= (1u << 20),
              "SinglePower batching loss log2(W) at 2^20 = 20 bits keeps "
              "field_rbr >= ~107 bits > 100-bit target");

/** STREAMING COLUMN-BLOCK COMMIT — prover FOOTPRINT tunables.
 *
 *  These are PROVER-LOCAL performance knobs. They are NOT protocol parameters:
 *  every commit/opening/proof byte is invariant under them (the absorption
 *  order into the row-leaf sponge is the column order, independent of how the
 *  columns are grouped into blocks). Changing them can only change how much
 *  memory the prover holds and how the work is scheduled.
 *
 *  Motivation (MEASURED): the arity-4 self-similar parent over real role
 *  children has W = 384,984 columns at n_rows = 256 (n_lde = 4096). A dense
 *  W x n_lde Fp3 extension is ~35 GiB and OOM-kills the prover. Blocking at
 *  K = 64 columns holds ~6 MiB of column LDE instead, so peak prover memory no
 *  longer depends on W at all.
 *
 *  kRCFri3AlgStreamColumnBlock is the nominal K (columns per block).
 *  kRCFri3AlgStreamBlockByteBudget caps K x n_lde x sizeof(Fp3) so a large LDE
 *  domain (up to the kRCFriMaxLdeLog2 = 24 ceiling) cannot reintroduce a large
 *  allocation; K is reduced, never the soundness parameters.
 *  Env overrides for experiments: BTX_FRI_STREAM_COLS, BTX_FRI_STREAM_BYTES. */
inline constexpr uint32_t kRCFri3AlgStreamColumnBlock = 64;
inline constexpr uint64_t kRCFri3AlgStreamBlockByteBudget =
    uint64_t{256} << 20; // 256 MiB
static_assert(kRCFri3AlgStreamColumnBlock >= 1,
              "streaming commit needs at least one column per block");

/** Largest DENSE column-LDE matrix (W x n_lde x sizeof(Fp3)) the prover is
 *  allowed to materialize before it switches to the streaming column-block
 *  commit. Above this the dense matrix is the whole memory problem: at the
 *  real-role arity-4 parent (W=384,984, n_lde=4096) it is ~35 GiB.
 *
 *  This is a FOOTPRINT threshold only. Both sides produce byte-identical
 *  proofs, so crossing it can never change a verifier outcome — it only
 *  chooses how much memory the prover holds. Env override:
 *  BTX_FRI_DENSE_LDE_BYTES (bytes; 0 = always stream). */
inline constexpr uint64_t kRCFri3AlgDenseLdeByteBudget =
    uint64_t{8} << 30; // 8 GiB

/**
 * True when a dense `columns x n_lde` Fp3 extension exceeds the prover
 * residency budget, i.e. when the streaming column-block commit must be used.
 * Pure function of shape — no transcript, no soundness parameter.
 */
[[nodiscard]] bool Fri3AlgShouldStreamColumns(uint64_t columns,
                                              uint32_t n_lde);

/** Bytes a dense `columns x n_lde` Fp3 extension would occupy (diagnostics). */
[[nodiscard]] uint64_t Fri3AlgDenseLdeBytes(uint64_t columns,
                                            uint32_t n_lde);

/** FAIL-CLOSED PEAK-RESIDENCY CEILING for one batch commit.
 *
 *  WHY THIS EXISTS: kRCFri3AlgBatchMaxColumns (2^20) is a COLUMN cap and is no
 *  longer an OOM guard — columns stopped predicting memory once n_lde grew.
 *  The MEASURED real-role arity-4 parent (W = 384,984, n_lde = 32,768) is
 *  comfortably UNDER the column cap yet its dense column LDE is
 *  384,984 x 32,768 x 24 B = 302.7 GiB. No machine here has that. Such a shape
 *  passes every existing guard and then gets the process OOM-killed, which has
 *  already cost this project a whole session.
 *
 *  So the commit projects its peak column-LDE residency in BYTES and refuses
 *  before allocating anything. This is a liveness guard, not a soundness gate:
 *  it never weakens a check, it converts an unsurvivable allocation into a
 *  clean, diagnosable `ok=false`. Env override: BTX_FRI_COMMIT_PEAK_BYTES. */
inline constexpr uint64_t kRCFri3AlgCommitPeakByteCeiling =
    uint64_t{48} << 30; // 48 GiB

/**
 * Projected peak prover-held bytes for one batch commit at this shape:
 * the column-LDE working set (dense = the whole W x n_lde matrix; streaming =
 * one K-column block) plus the row-leaf/Merkle working set.
 */
[[nodiscard]] uint64_t Fri3AlgProjectedCommitPeakBytes(uint64_t columns,
                                                       uint32_t n_lde,
                                                       bool streaming);

/**
 * Fail-closed admission check. Returns false (and fills `why` / `projected`)
 * when the shape's projected peak exceeds the ceiling, so callers reject
 * BEFORE allocating rather than being OOM-killed mid-commit.
 */
[[nodiscard]] bool Fri3AlgCommitFitsMemoryBudget(uint64_t columns,
                                                 uint32_t n_lde,
                                                 bool streaming,
                                                 uint64_t* projected,
                                                 std::string* why);

static_assert(kRCFri3AlgNumQueries == 192,
              "Stage-3 recursion FRI ships Q=192");
static_assert(kRCFriGrindingBits == 40, "recursion FRI ships g=40 (spec §5.2)");
static_assert(kRCFriBlowup == 16, "recursion FRI ships blowup=16 (spec §5.2)");
static_assert(kRCFri3AlgMaxQueriesHard >= kRCFri3AlgNumQueries,
              "path-local hard cap must admit Q=192");
static_assert(kRCFri3AlgFormalSoundnessReady,
              "single-lane rbr/BCS reduction machine-checked by "
              "AssessFri3AlgBcsRbrLedgerV1 (gate 3)");

// Experimental two-fold challenge repetition of the complete algebraic-FRI
// verifier. The baseline Q192/V3 protocol above remains unchanged. Each lane
// is a full Q128/V5 proof of the same row commitment and every SHA-based FS
// draw is replayed under a disjoint lane prefix; BOTH ordered lanes must pass.
// V5 also replaces the one-power column batching challenge by W independently
// sampled Fp3 coefficients. The outer V2 envelope commits to one common master
// statement and two ordered lane-child bindings.
//
// This is still NOT the full-oracle separation rho_i(x)=rho(i||x) required by
// the BCS parallel-repetition lemma. V5 exposes both the selected shared-master
// construction and an executable alternative that prefixes every AlgHash
// row/fold leaf and internal node input by lane. The exact NIROP/BCS reduction
// for either construction is not complete. The executable binding envelope
// makes substitution fail closed and exposes an auditable hybrid boundary; it
// is not itself the reduction. No squared soundness claim is made while that
// proof is absent.
inline constexpr uint32_t kRCFri3AlgDualProofMagic = 0x32444641u; // 'AFD2'
inline constexpr uint32_t kRCFri3AlgDualProofVersion = 2;
inline constexpr uint32_t kRCFri3AlgDualLaneProofVersion = 5;
inline constexpr uint32_t kRCFri3AlgDualNumLanes = 2;
inline constexpr uint32_t kRCFri3AlgDualQueriesPerLane = 128;
inline constexpr uint32_t kRCFri3AlgDualTotalQueries =
    kRCFri3AlgDualNumLanes * kRCFri3AlgDualQueriesPerLane;
inline constexpr uint32_t kRCFri3AlgDualOodCandidates = 2;
inline constexpr uint32_t kRCFri3AlgDualUniformHashBlocks = 2;
inline constexpr uint32_t kRCFri3AlgDualUniformWords =
    4 * kRCFri3AlgDualUniformHashBlocks;
inline constexpr char kRCFri3AlgDualDomainTag[] = "BTX_RC_FRIB3ALG_DUAL_Q128_V2";
inline constexpr char kRCFri3AlgDualLane0DomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q128_V5_LANE0";
inline constexpr char kRCFri3AlgDualLane1DomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q128_V5_LANE1";
inline constexpr char kRCFri3AlgDualUniformDrawDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_UNIFORM_FP3_V1";
inline constexpr char kRCFri3AlgDualIndexDrawDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_UNIFORM_INDEX_V1";
inline constexpr char kRCFri3AlgDualMasterBindingDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_MASTER_BINDING_V1";
inline constexpr char kRCFri3AlgDualChildBindingDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_CHILD_BINDING_V1";
inline constexpr size_t kRCFri3AlgDualMaxProofBytesHard =
    2 * kRCFriMaxProofBytesHard + 128;
inline constexpr uint32_t kRCFri3AlgDualAlgHashCollisionBits = 128;
inline constexpr bool kRCFri3AlgDualAlgHashInputsLanePrefixed = true;
inline constexpr bool kRCFri3AlgDualFullOracleDomainSeparated = false;
inline constexpr bool kRCFri3AlgDualIndependenceReductionReady = false;
inline constexpr bool kRCFri3AlgDualFormalSoundnessReady = false;
static_assert(kRCFri3AlgDualNumLanes == 2);
static_assert(kRCFri3AlgDualTotalQueries <=
              kRCFri3AlgMaxQueriesHard * kRCFri3AlgDualNumLanes);
static_assert(kRCFri3AlgDualOodCandidates == 2);
static_assert(kRCFri3AlgDualUniformWords == 8);
static_assert(!kRCFri3AlgDualFullOracleDomainSeparated);
static_assert(!kRCFri3AlgDualIndependenceReductionReady);
static_assert(!kRCFri3AlgDualFormalSoundnessReady);

// Versioned high-margin experiment. This is deliberately additive: the
// deployed R&D V5/Q128 codec and transcript remain byte-for-byte unchanged.
// V6 raises each independently batched, domain-separated lane to Q=136.
// Its executable proximity screen clears 100 bits after the exact current
// site union/grinding accounting, but authority remains false until the
// NIROP/common-commitment and global-composition reductions close.
inline constexpr uint32_t kRCFri3AlgDualQ136ProofMagic =
    0x36444641u; // 'AFD6'
inline constexpr uint32_t kRCFri3AlgDualQ136ProofVersion = 3;
inline constexpr uint32_t kRCFri3AlgDualQ136LaneProofVersion = 6;
inline constexpr uint32_t kRCFri3AlgDualQ136QueriesPerLane = 136;
inline constexpr uint32_t kRCFri3AlgDualQ136TotalQueries =
    kRCFri3AlgDualNumLanes *
    kRCFri3AlgDualQ136QueriesPerLane;
inline constexpr char kRCFri3AlgDualQ136DomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_V3";
inline constexpr char kRCFri3AlgDualQ136Lane0DomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_V6_LANE0";
inline constexpr char kRCFri3AlgDualQ136Lane1DomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_V6_LANE1";
inline constexpr char kRCFri3AlgDualQ136UniformDrawDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_UNIFORM_FP3_V1";
inline constexpr char kRCFri3AlgDualQ136IndexDrawDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_UNIFORM_INDEX_V1";
inline constexpr char kRCFri3AlgDualQ136MasterBindingDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_MASTER_BINDING_V1";
inline constexpr char kRCFri3AlgDualQ136ChildBindingDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_CHILD_BINDING_V1";
inline constexpr size_t kRCFri3AlgDualQ136MaxProofBytesHard =
    2 * kRCFriMaxProofBytesHard + 128;
inline constexpr bool
    kRCFri3AlgDualQ136FullOracleDomainSeparated = false;
inline constexpr bool
    kRCFri3AlgDualQ136IndependenceReductionReady = false;
inline constexpr bool
    kRCFri3AlgDualQ136FormalSoundnessReady = false;
static_assert(
    kRCFri3AlgDualQ136QueriesPerLane <=
    kRCFri3AlgMaxQueriesHard);
static_assert(
    kRCFri3AlgDualQ136TotalQueries ==
    272);
static_assert(
    !kRCFri3AlgDualQ136FullOracleDomainSeparated);
static_assert(
    !kRCFri3AlgDualQ136IndependenceReductionReady);
static_assert(
    !kRCFri3AlgDualQ136FormalSoundnessReady);

// Raw query-phase proximity term, FIELD-INDEPENDENT: floor(Q·log2(32/17)).
// This is the UNIQUE-DECODING proximity soundness assuming a NON-GRINDABLE
// (random-oracle) query-index draw; it carries NO grinding term of either sign.
// At Q=192 this is 175 (real 175.21).
[[nodiscard]] inline int Fri3AlgProximityBoundBits()
{
    constexpr uint64_t kLog2_32_17_Q32 = 3919317253ull; // log2(32/17) in Q32
    const uint64_t prod = static_cast<uint64_t>(kRCFri3AlgNumQueries) * kLog2_32_17_Q32;
    return static_cast<int>(prod >> 32);
}

// PR-89 re-refutation (lemma-5 tax-ledger reconciliation). The grinding term g
// has ONE consistent meaning across the whole accounting: it is a CREDIT (+g)
// that is legitimately earned ONLY on a path whose VERIFIER checks the enforced
// per-squeeze predicate Fri3AlgCheckSqueezeGrind (the Π_JQ deciding squeeze —
// see Fri3AlgJointQBatchVerify, which rejects a sub-g nonce, and the +g the
// Fri3AlgHonestDualFloorBits floor books).
//
// The single-lane Q192 verify (the ext3 Fri3AlgBatchVerify path) does NOT check
// that predicate: it absorbs pow_grind_nonce into the FS seed but never tests
// the g-leading-zero condition. This flag records that fact so the ledger cannot
// silently claim an unearned +g credit on this untaxed path.
inline constexpr bool kRCFri3AlgSingleLaneEnforcesSqueezeGrind = false;
static_assert(!kRCFri3AlgSingleLaneEnforcesSqueezeGrind,
              "single-lane Q192 verify does not check Fri3AlgCheckSqueezeGrind; "
              "it earns no enforced-tax credit (only Π_JQ-taxed paths do)");

// Because the single-lane path forfeits the +g credit, the un-predicated
// last-round regrind is charged CONSERVATIVELY as an adversary grind-budget
// DEDUCTION of this many bits (numerically kRCFriGrindingBits, but a DEDUCTION
// here, NOT the enforced credit). This is the honest per-path replacement for
// the old flat "proximity − g" that ambiguously reused the enforced-tax constant
// with the opposite sign to the dual floor.
inline constexpr uint32_t kRCFri3AlgUnenforcedRegrindBudgetBits =
    kRCFriGrindingBits;

// +g enforced-tax credit, SOURCED from the verifier-checked predicate. `enforced`
// MUST reflect the actual verify wiring on the path being scored; passing true
// where Fri3AlgCheckSqueezeGrind is not in the verify path is a ledger lie. Only
// the Π_JQ path (Fri3AlgJointQBatchVerify) may pass enforced=true.
[[nodiscard]] inline int Fri3AlgEnforcedSqueezeGrindCreditBits(bool enforced,
                                                               uint32_t g)
{
    return enforced ? static_cast<int>(g) : 0;
}

// Single-lane Q192 proximity-screen soundness. Per-path honest g accounting:
//   enforced credit (this path):  Fri3AlgEnforcedSqueezeGrindCreditBits(false,·)=0
//   unenforced regrind deduction: −kRCFri3AlgUnenforcedRegrindBudgetBits
// => floor(192·log2(32/17)) − 40 = 135. The −40 is a CONSERVATIVE deduction for
// the un-predicated regrind, NOT the +g enforced credit the Π_JQ floor books;
// the two are now DISTINCT quantities, which resolves the old sign contradiction
// (same constant appearing as both −40 here and +40 in the dual floor).
[[nodiscard]] inline int Fri3AlgSoundnessBoundBits()
{
    return Fri3AlgProximityBoundBits() +
           Fri3AlgEnforcedSqueezeGrindCreditBits(
               kRCFri3AlgSingleLaneEnforcesSqueezeGrind, kRCFriGrindingBits) -
           static_cast<int>(kRCFri3AlgUnenforcedRegrindBudgetBits);
}

inline constexpr char kRCFri3AlgBatchSoundnessStatement[] =
    "BATCHED FRI (Fp3 substrate, v5 fold, ALGEBRAIC Poseidon2-Goldilocks "
    "Merkle, ROW-WISE layout): ONE instance over ALL committed columns; ONE "
    "row tree (leaf i = LeafHashRow of all W column values at row i) => one "
    "opening path per query. Q=192, blowup=16, g=40, Fp3 (|F|=p^3~2^192), "
    "UNIQUE-DECODING alpha=17/32 => Fri3AlgSoundnessBoundBits()=135 (real "
    "135.21 per proof; 107.21 after a 2^28-site union diagnostic). v5 "
    "half-domain fold × log2(n_coeffs) → terminal B-constant layer. DUAL-OOD "
    "DEEP (z1,z2) with extension part (c1,c2)!=(0,0); degree-shift RLC "
    "enforces per-column maximal degree — both unchanged from the SHA batch "
    "path. FS transcript SHA256d (not arithmetized); Merkle field-native. "
    "Collision resistance of the 4-lane capacity sponge: 2^-128 floor. "
    "COMPUTATIONAL — not eps=0.";

/**
 * Canonical 4×Fp ⇆ uint256 packing: byte [8k, 8k+8) = LE64(Canonical(d[k])).
 * Used ONLY at the FS-transcript and serialization boundaries.
 */
[[nodiscard]] uint256 Fri3AlgDigestToUint256(const Fri3AlgDigest& d);

/** Inverse packing; rejects (nullopt) any limb ≥ p — non-canonical encodings
 *  are invalid, so the packing is a bijection onto its image. */
[[nodiscard]] std::optional<Fri3AlgDigest> Fri3AlgDigestFromUint256(const uint256& u);

/**
 * Decode one 24-byte unbiased Fp3 candidate. Each LE64 limb must be < p;
 * unlike FromChallengeBytes3 this never reduces modulo p. V5 uses this in a
 * bounded rejection sampler. Exposed so forced-rejection vectors can pin the
 * consensus-critical canonicality rule.
 */
[[nodiscard]] std::optional<Fp3> Fri3AlgDecodeUniformFp3Candidate(
    const std::array<unsigned char, 24>& candidate);
[[nodiscard]] std::optional<Fp3> Fri3AlgSelectUniformFp3Words(
    const std::array<uint64_t, kRCFri3AlgDualUniformWords>& words);

/** Test/audit hook for the streaming SHA256 prefix optimization.  Every
 * challenge label used by V3 and V5 is compared against the legacy
 * concatenate-then-SHA256d construction at multiple transcript offsets. */
struct Fri3AlgStreamingFsAudit {
    uint32_t legacy_fp3_vectors{0};
    uint32_t uniform_fp3_vectors{0};
    uint32_t uniform_index_vectors{0};
    bool legacy_fp3_match{false};
    bool uniform_fp3_match{false};
    bool uniform_index_match{false};
    bool all_match{false};
    std::string note;
};

[[nodiscard]] Fri3AlgStreamingFsAudit
AuditFri3AlgStreamingFs(const uint256& fs_seed);

struct Fri3AlgStreamingProverPlan {
    uint32_t batch_columns{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    uint32_t query_openings{0};
    uint32_t column_lde_passes{0};
    uint64_t materialized_column_lde_bytes{0};
    uint64_t row_sponge_bytes{0};
    uint64_t row_merkle_bytes{0};
    uint64_t one_column_recompute_bytes{0};
    uint64_t composition_coeff_bytes{0};
    uint64_t retained_query_value_bytes{0};
    uint64_t fold_recompute_peak_bytes{0};
    uint64_t streaming_peak_bytes{0};
    double materialization_reduction_ratio{0.0};
    bool shape_valid{false};
    bool under_four_gib{false};
    bool executable_row_hash_primitive{false};
    bool complete_streaming_prover{false};
    std::string note;
};

using Fri3AlgFoldLayerWriteCallback =
    std::function<bool(
        uint32_t lane,
        uint32_t layer,
        const std::vector<Fp3>& values,
        std::string* why)>;
using Fri3AlgFoldLayerReadCallback =
    std::function<bool(
        uint32_t lane,
        uint32_t layer,
        uint32_t count,
        std::vector<Fp3>& values,
        std::string* why)>;

struct Fri3AlgFoldSpillReplayAudit {
    uint32_t lanes{0};
    uint32_t layers_spilled{0};
    uint32_t paths_replayed{0};
    uint64_t evaluations_spilled{0};
    bool fold_values_roundtrip{false};
    bool layer_roots_identical{false};
    bool query_paths_identical{false};
    bool dense_proof_bytes_identical{false};
    bool streaming_proof_bytes_identical{false};
    bool replayed_proof_verified{false};
    bool executable_bounded_audit{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] Fri3AlgFoldSpillReplayAudit
AuditFri3AlgDualFoldSpillReplay(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    const Fri3AlgFoldLayerWriteCallback& write_layer,
    const Fri3AlgFoldLayerReadCallback& read_layer,
    uint64_t pow_grind_nonce = 0);

inline constexpr bool
    kFri3AlgBoundedFoldSpillReplayAuditExecutable = true;
static_assert(
    kFri3AlgBoundedFoldSpillReplayAuditExecutable);

/** Exact memory plan for the two-pass column-streaming row-tree prover. */
[[nodiscard]] Fri3AlgStreamingProverPlan
AssessFri3AlgStreamingProverPlan(
    uint32_t batch_columns, uint32_t n_coeffs,
    uint32_t query_openings = kRCFri3AlgDualTotalQueries);

/** Layer commitment with a field-native root (FriLayerCommit analogue). */
struct Fri3AlgLayerCommit {
    Fri3AlgDigest root{};
    uint32_t n_leaves{0};
};

/** Fold-step opening (Fri3FoldStep with Fp^4 sibling digests). */
struct Fri3AlgFoldStep {
    /** Pair indices on domain size N: even_index = i, odd_index = i + N/2. */
    uint32_t even_index{0};
    uint32_t odd_index{0};
    Fp3 even{}; // f(x) at i
    Fp3 odd{};  // f(-x) at i+N/2
    std::vector<Fri3AlgDigest> even_siblings;
    std::vector<Fri3AlgDigest> odd_siblings;
};

/** Row opening at one query index: ALL W column values + ONE path (§2.3). */
struct Fri3AlgRowOpening {
    /** values[i] = column i's LDE value at the query index, column order. */
    std::vector<Fp3> values;
    std::vector<Fri3AlgDigest> siblings;
};

struct Fri3AlgBatchQuery {
    uint32_t index{0};
    /** One row opening against row_commit (replaces W per-column openings). */
    Fri3AlgRowOpening row;
    /** Fold-path openings of the DEEP composition G (same math as SHA path). */
    std::vector<Fri3AlgFoldStep> steps;
};

/** Fri3BatchProof analogue (spec §2.4): per-column FriLayerCommit roots →
 *  a SINGLE row-wise commitment; all digests Fp^4; everything else identical
 *  in meaning (lambda, z1, z2, evals_z1/z2, w1, w2, fold layers, final_value,
 *  fold_challenges, pow_grind_nonce, n_coeffs, blowup). */
struct Fri3AlgBatchProof {
    uint32_t version{kRCFri3AlgActiveBatchProofVersion};
    uint64_t pow_grind_nonce{0};
    uint32_t blowup{kRCFriBlowup};
    /** Common padded column length N (power of two); LDE domain = N·blowup. */
    uint32_t n_coeffs{0};
    /** SINGLE row-wise Merkle commitment over the common LDE domain (§2.3). */
    Fri3AlgLayerCommit row_commit{};
    /** Logical (pre-padding) length ℓ_i of each column = enforced degree bound. */
    std::vector<uint32_t> column_len;
    /** FS RLC challenge (recomputed and checked by the verifier). */
    Fp3 lambda{};
    /** Dual OOD points (FS, both ∉ D, z1 ≠ z2). */
    Fp3 z1{};
    Fp3 z2{};
    /** Claimed per-column evaluations at z1/z2 — THE bound opening primitive. */
    std::vector<Fp3> evals_z1;
    std::vector<Fp3> evals_z2;
    /** FS DEEP batching weights (recomputed and checked). */
    Fp3 w1{};
    Fp3 w2{};
    /** Fold-commit layers of the DEEP composition G (field-native roots). */
    std::vector<Fri3AlgLayerCommit> fold_layers;
    Fp3 final_value{};
    std::vector<Fp3> fold_challenges;
    std::vector<Fri3AlgBatchQuery> queries;
};

inline constexpr uint32_t
    kRCFri3AlgMultiRowBatchProofVersion = 2;
inline constexpr uint32_t
    kRCFri3AlgMultiRowBatchProofMagic =
        0x32524d46u; // 'FMR2'
inline constexpr uint32_t
    kRCFri3AlgMultiRowMaxGroups = 8;
/** Consensus-facing decoder bound. The executable canonical V2 codec
 * rejects larger inputs before allocating any attacker-sized vector. */
inline constexpr size_t
    kRCFri3AlgMultiRowMaxProofBytesHard =
        kRCFriMaxProofBytesHard;

enum class Fri3AlgMultiRowGroupRole : uint8_t {
    MainTrace = 1,
    AuxiliaryTrace = 2,
    Quotient = 3,
};

struct Fri3AlgMultiRowGroupCommit {
    Fri3AlgMultiRowGroupRole role{
        Fri3AlgMultiRowGroupRole::MainTrace};
    uint32_t first_column{0};
    uint32_t column_count{0};
    Fri3AlgLayerCommit row_commit{};
};

struct Fri3AlgMultiRowBatchQuery {
    uint32_t index{0};
    /** Exactly one row opening per ordered group at this shared index. */
    std::vector<Fri3AlgRowOpening> group_rows;
    std::vector<Fri3AlgFoldStep> steps;
};

/**
 * Multi-segment RAP batch proof. Each logical polynomial occurs in exactly
 * one ordered group commitment. V2 transcript order is roots/metadata,
 * dual-OOD points, all ordered individual evaluation claims, and only then
 * independent column batching. Drawing the batching vector after the claims
 * is essential: otherwise adaptive kernel deltas could preserve the two
 * aggregate evaluations while forging individual OOD cells. DEEP weights,
 * folds and shared queries follow.
 */
struct Fri3AlgMultiRowBatchProof {
    uint32_t version{
        kRCFri3AlgMultiRowBatchProofVersion};
    uint64_t pow_grind_nonce{0};
    uint32_t blowup{kRCFriBlowup};
    uint32_t n_coeffs{0};
    std::vector<Fri3AlgMultiRowGroupCommit> groups;
    std::vector<uint32_t> column_len;
    Fp3 lambda{};
    Fp3 z1{};
    Fp3 z2{};
    std::vector<Fp3> evals_z1;
    std::vector<Fp3> evals_z2;
    Fp3 w1{};
    Fp3 w2{};
    std::vector<Fri3AlgLayerCommit> fold_layers;
    Fp3 final_value{};
    std::vector<Fp3> fold_challenges;
    std::vector<Fri3AlgMultiRowBatchQuery> queries;
};

struct Fri3AlgRowTreeCache;

struct Fri3AlgMultiRowBatchCommitResult {
    Fri3AlgMultiRowBatchProof proof;
    std::vector<std::shared_ptr<Fri3AlgRowTreeCache>>
        group_row_tree_caches;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

/**
 * Executable regression for the V1 adaptive-evaluation kernel bug. It
 * constructs nonzero per-column deltas that preserve both old-schedule
 * aggregate OOD values, then confirms V2's post-claim batching challenge
 * changes and the mutated V2 proof is rejected.
 */
struct Fri3AlgMultiRowPostClaimBindingAudit {
    bool legacy_nonzero_kernel_constructed{false};
    bool legacy_aggregate_z1_preserved{false};
    bool legacy_aggregate_z2_preserved{false};
    bool fixed_batch_challenge_changed{false};
    bool fixed_verifier_rejected{false};
    bool valid{false};
    std::string note;
};

/** Prover-local checked cache for one shared row tree. Never serialized. */
struct Fri3AlgRowTreeCache {
    uint16_t version{1};
    uint32_t columns{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    std::vector<uint32_t> column_len;
    uint256 coefficient_commitment{};
    std::vector<std::vector<Fri3AlgDigest>> levels;
    Fri3AlgDigest root{};
    bool valid{false};
};

struct Fri3AlgBatchCommitResult {
    Fri3AlgBatchProof proof;
    /** Per-column LDE over the common domain (prover-side; NEVER shipped). */
    std::vector<std::vector<Fp3>> column_lde;
    /** Checked row-tree session retained only by the streaming prover. */
    std::shared_ptr<Fri3AlgRowTreeCache> row_tree_cache;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

/**
 * Experimental dual-Q128 envelope. Lane position is semantic: lane[0] and
 * lane[1] use distinct transcript prefixes and cannot be swapped or copied.
 * Both lanes carry the same public shape/nonce. The selected wrapper uses one
 * shared AlgHash row root; the explicit duplicated scenario uses distinct
 * lane-prefixed roots. Master and ordered child bindings are recomputed by the
 * verifier from both roots and the caller-authenticated fs_seed.
 */
struct Fri3AlgDualBatchProof {
    uint32_t version{kRCFri3AlgDualProofVersion};
    uint256 master_statement_binding{};
    std::array<uint256, kRCFri3AlgDualNumLanes> lane_child_binding{};
    std::array<Fri3AlgBatchProof, kRCFri3AlgDualNumLanes> lane{};
};

struct Fri3AlgDualBatchCommitResult {
    Fri3AlgDualBatchProof proof;
    /** Shared prover-side LDE, retained for the experimental AIR policy. */
    std::vector<std::vector<Fp3>> column_lde;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

/**
 * Diagnostic-only honest proof fixture for the all-zero polynomial family.
 *
 * This specialized builder constructs the exact index-bound row/fold Merkle
 * trees and canonical V5 transcript, but skips coefficient LDE/FFT work
 * because every one of the batch_columns polynomials is identically zero.
 * It exists solely to exercise and time the real combined-width/depth native
 * verifier.  It is NOT an episode relation proof, a production prover-cost
 * measurement, a recursion closure, or authority-readiness evidence.
 */
struct Fri3AlgDualZeroVerifierFixtureResult {
    Fri3AlgDualBatchProof proof;
    size_t proof_bytes{0};
    uint64_t merkle_nodes_built{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] Fri3AlgDualZeroVerifierFixtureResult
BuildFri3AlgDualZeroVerifierFixture(
    uint32_t batch_columns, uint32_t n_coeffs,
    const uint256& fs_seed, uint64_t pow_grind_nonce = 0);

/**
 * Canonical finite V5 transcript schedule. Unlike the legacy V3 program,
 * every draw count is fixed: W independent coefficients, four OOD
 * candidates, two DEEP weights, log2(N) folds and Q=128 indices per lane.
 */
struct Fri3AlgDualTranscriptProgram {
    uint32_t envelope_version{kRCFri3AlgDualProofVersion};
    uint32_t lane_version{kRCFri3AlgDualLaneProofVersion};
    uint32_t lanes{kRCFri3AlgDualNumLanes};
    uint32_t batch_columns{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    uint32_t fold_challenges_per_lane{0};
    uint32_t queries_per_lane{kRCFri3AlgDualQueriesPerLane};
    uint32_t independent_batch_draws_per_lane{0};
    uint32_t ood_draws_per_lane{
        2 * kRCFri3AlgDualOodCandidates};
    uint32_t deep_weight_draws_per_lane{2};
    uint64_t uniform_fp3_draws_per_lane{0};
    uint64_t uniform_fp3_hashes_per_lane{0};
    uint64_t query_index_hashes_per_lane{0};
    uint64_t challenge_hashes_total{0};
    bool fixed_ood_schedule{false};
    bool independent_batching{false};
    bool lane_order_semantic{false};
    bool valid{false};
    std::string note;
};

struct Fri3AlgDualLaneTranscriptWitness {
    uint32_t lane{0};
    uint256 lane_seed{};
    std::vector<Fp3> batch_coefficients;
    std::array<Fp3, 2 * kRCFri3AlgDualOodCandidates>
        ood_candidates{};
    Fp3 selected_z1{};
    Fp3 selected_z2{};
    Fp3 w1{};
    Fp3 w2{};
    std::vector<Fp3> fold_challenges;
    std::vector<uint32_t> query_indices;
    bool independent_coefficients_replayed{false};
    bool fixed_ood_schedule_replayed{false};
    bool folds_replayed{false};
    bool queries_replayed{false};
    bool valid{false};
    std::string note;
};

/** Complete proof-derived host witness of both ordered V5 lane transcripts. */
struct Fri3AlgDualTranscriptWitness {
    Fri3AlgDualTranscriptProgram program{};
    uint256 master_statement_binding{};
    std::array<uint256, kRCFri3AlgDualNumLanes>
        lane_child_binding{};
    std::array<Fri3AlgDualLaneTranscriptWitness,
               kRCFri3AlgDualNumLanes>
        lane{};
    bool common_statement_bound{false};
    bool ordered_lanes_bound{false};
    bool valid{false};
    std::string note;
};

enum class Fri3AlgDualCommitmentScenario : uint8_t;

/**
 * Verify one field-native Merkle authentication path: fold leaf_digest up
 * with alg_hash::Compress against siblings. The caller computes leaf_digest
 * (alg_hash::LeafHash for fold layers, alg_hash::LeafHashRow for the row
 * tree) — leaf/node domain separation lives in the capacity seeds Le ≠ D.
 */
[[nodiscard]] bool Fri3AlgVerifyPath(const Fri3AlgDigest& leaf_digest, uint32_t index,
                                     const std::vector<Fri3AlgDigest>& siblings,
                                     const Fri3AlgDigest& root, uint32_t n_leaves);

/**
 * Commit-and-prove: ONE batched FRI instance over all columns, row-wise
 * algebraic Merkle layout. columns[i] = coefficient vector; size = logical
 * length ℓ_i ≥ 1. fs_seed MUST already bind everything the caller committed
 * to — commit-then-challenge.
 */
[[nodiscard]] Fri3AlgBatchCommitResult Fri3AlgBatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);

/** Q192 single-lane two-pass row commit. Proof bytes are identical to the
 * dense prover while prover-side `column_lde` is empty. */
[[nodiscard]] Fri3AlgBatchCommitResult
Fri3AlgBatchCommitStreamingShared(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);

[[nodiscard]] Fri3AlgBatchCommitResult
Fri3AlgBatchCommitStreamingSharedCached(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);

[[nodiscard]] bool Fri3AlgBuildRowTreeCacheStreaming(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs,
    Fri3AlgRowTreeCache& out,
    std::string* why = nullptr);

/** Recompute selected row openings against an existing shared row root.
 * Pass 1 builds the tree one column LDE at a time; pass 2 retains only the
 * requested values. No W×N_LDE field matrix is retained. */
[[nodiscard]] bool Fri3AlgOpenRowsStreamingShared(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs,
    const std::vector<uint32_t>& indices,
    const Fri3AlgDigest& expected_root,
    std::vector<Fri3AlgRowOpening>& out,
    std::string* why = nullptr);

[[nodiscard]] bool Fri3AlgOpenRowsStreamingSharedCached(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs,
    const std::vector<uint32_t>& indices,
    const Fri3AlgDigest& expected_root,
    const Fri3AlgRowTreeCache& cache,
    std::vector<Fri3AlgRowOpening>& out,
    std::string* why = nullptr);

[[nodiscard]] bool Fri3AlgBatchVerify(const Fri3AlgBatchProof& proof, const uint256& fs_seed,
                                      std::string* why = nullptr);

/**
 * PR-89 blocker #6 (H1): single-lane transcript-coefficient replay.
 *
 * Re-derives the W = column_len.size() batching coefficients that the honest
 * prover drew from the FS transcript under kFri3AlgQ192V3Config, exactly as
 * Fri3AlgBatchVerifyConfigured does (ProtocolBatchCoefficients). The proof
 * stores only the scalar `lambda` (= coefficients[0]), so the full independent
 * vector must be recovered by transcript replay at extract/verify time. On
 * success `out_coefficients.size() == column_len.size()` and, when the Q192
 * config uses legacy one-power batching, the returned vector is exactly
 * [1, lambda, lambda^2, ...]; under independent-coefficient batching it is the
 * W independently sampled fra3_batch_coeff draws. Returns false (and clears the
 * output) on any shape mismatch or if the replayed encoded scalar does not bind
 * proof.lambda. This is the single-lane analogue of the per-lane
 * batch_coefficients produced by BuildFri3AlgDualTranscriptWitness.
 */
[[nodiscard]] bool Fri3AlgReplayBatchCoefficients(const Fri3AlgBatchProof& proof,
                                                  const uint256& fs_seed,
                                                  std::vector<Fp3>& out_coefficients);

/** True iff kFri3AlgQ192V3Config draws independent batching coefficients
 *  (PR-89 blocker #6). Exposed so the recursion (air_recurse /
 *  recursive_fixedpoint), which cannot see the file-local config, can decide
 *  whether to thread the replayed independent vector into public inputs. */
[[nodiscard]] bool Fri3AlgQ192IndependentBatching();

/**
 * Streaming ordered multi-segment batched FRI. `groups[g]` contains
 * coefficient-form polynomials for exactly one committed row oracle.
 * `roles` must be the canonical MainTrace/AuxiliaryTrace/Quotient order.
 * Optional retained caches are checked hints and must match the exact group
 * coefficients; they are never serialized or trusted.
 */
[[nodiscard]] Fri3AlgMultiRowBatchCommitResult
Fri3AlgMultiRowBatchCommitStreaming(
    const std::vector<std::vector<std::vector<Fp3>>>& groups,
    const std::vector<Fri3AlgMultiRowGroupRole>& roles,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0,
    const std::vector<
        std::shared_ptr<Fri3AlgRowTreeCache>>&
        retained_group_caches = {});

[[nodiscard]] bool Fri3AlgMultiRowBatchVerify(
    const Fri3AlgMultiRowBatchProof& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);

/** Canonical, byte-unique V2 multi-row RAP proof envelope. Serialization
 * fails closed (returns zero and clears `out`) for every noncanonical
 * role/range/domain/query/path/fold shape or proof exceeding the hard cap. */
[[nodiscard]] size_t SerializeFri3AlgMultiRowBatchProof(
    const Fri3AlgMultiRowBatchProof& proof,
    std::vector<unsigned char>& out);
[[nodiscard]] std::optional<Fri3AlgMultiRowBatchProof>
DeserializeFri3AlgMultiRowBatchProof(
    const std::vector<unsigned char>& in);

[[nodiscard]] Fri3AlgMultiRowPostClaimBindingAudit
AuditFri3AlgMultiRowPostClaimBinding(
    const std::vector<std::vector<std::vector<Fp3>>>& groups,
    const std::vector<Fri3AlgMultiRowGroupRole>& roles,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);

/**
 * Standalone row-root helper (two-epoch discipline; Fri3BatchColumnRoot
 * analogue for the ROW-WISE layout): the Merkle root of the row tree over the
 * common LDE domain of padded size n_coeffs, from the full column set.
 * Limb-identical to proof.row_commit.root produced by Fri3AlgBatchCommit for
 * the same (columns, n_coeffs). Returns the all-zero digest on invalid input.
 * NOTE: a PER-column root has no meaning in the row-wise layout — the row
 * tree is the unit of commitment (spec §2.3).
 */
[[nodiscard]] Fri3AlgDigest Fri3AlgBatchRowRoot(const std::vector<std::vector<Fp3>>& columns,
                                                uint32_t n_coeffs);

/** Column-at-a-time equivalent of Fri3AlgBatchRowRoot. */
[[nodiscard]] Fri3AlgDigest Fri3AlgBatchRowRootStreaming(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs);

/**
 * Forge probe (Fri3ForgeFlippedEvalMustFail analogue): flip ONE LDE eval of
 * column flip_col at LDE index flip_index, recompute ONLY the row root, keep
 * the honest openings; returns true iff Fri3AlgBatchVerify correctly rejects.
 */
[[nodiscard]] bool Fri3AlgForgeFlippedEvalMustFail(const Fri3AlgBatchCommitResult& honest,
                                                   const uint256& fs_seed, uint32_t flip_col,
                                                   uint32_t flip_index,
                                                   std::string* why = nullptr);

[[nodiscard]] size_t SerializeFri3AlgBatchProof(const Fri3AlgBatchProof& proof,
                                                std::vector<unsigned char>& out);
[[nodiscard]] std::optional<Fri3AlgBatchProof> DeserializeFri3AlgBatchProof(
    const std::vector<unsigned char>& in);

/**
 * Experimental complete two-lane challenge repetition. Every SHA-based FS
 * query includes its lane's disjoint prefix. Both lanes prove the same
 * row-wise commitment and carry exactly Q=128 queries, with independently
 * sampled per-column batching coefficients and lane-prefixed AlgHash trees.
 * This API is still not a completed BCS parallel repetition until the exact
 * transcript/oracle-domain reduction is written and composed globally.
 */
[[nodiscard]] Fri3AlgDualBatchCommitResult Fri3AlgDualBatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);

/**
 * Selected shared-master V5 prover with bounded column-LDE residency.
 *
 * Pass 1 recomputes one column LDE at a time into StreamingRowHasher and
 * commits one row tree, which is reused by both lanes. After each lane's
 * complete fold transcript fixes its query indices, pass 2 recomputes one
 * column LDE at a time and retains only queried row values. The returned
 * prover-side column_lde is intentionally empty. This is proof-byte equivalent
 * to Fri3AlgDualBatchCommit for the same input.
 */
[[nodiscard]] Fri3AlgDualBatchCommitResult
Fri3AlgDualBatchCommitStreamingShared(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);

[[nodiscard]] bool Fri3AlgDualBatchVerify(const Fri3AlgDualBatchProof& proof,
                                          const uint256& fs_seed,
                                          std::string* why = nullptr);
[[nodiscard]] Fri3AlgDualTranscriptProgram
BuildFri3AlgDualTranscriptProgram(
    const Fri3AlgDualBatchProof& proof);
[[nodiscard]] Fri3AlgDualTranscriptWitness
BuildFri3AlgDualTranscriptWitness(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed);
[[nodiscard]] Fri3AlgDualBatchCommitResult
Fri3AlgDualBatchCommitForScenario(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    Fri3AlgDualCommitmentScenario scenario,
    uint64_t pow_grind_nonce = 0);
[[nodiscard]] bool Fri3AlgDualBatchVerifyForScenario(
    const Fri3AlgDualBatchProof& proof, const uint256& fs_seed,
    Fri3AlgDualCommitmentScenario scenario,
    std::string* why = nullptr);
[[nodiscard]] size_t SerializeFri3AlgDualBatchProof(
    const Fri3AlgDualBatchProof& proof, std::vector<unsigned char>& out);
[[nodiscard]] std::optional<Fri3AlgDualBatchProof> DeserializeFri3AlgDualBatchProof(
    const std::vector<unsigned char>& in);

/**
 * Additive V6/Q136 experiment. It reuses the dual proof data model but has a
 * distinct envelope magic/version, lane version, transcript domains, query
 * cap, bindings and codec entry points. Both ordered lanes must verify.
 */
[[nodiscard]] Fri3AlgDualBatchCommitResult
Fri3AlgDualQ136BatchCommit(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);
/**
 * Explicit Q136 commitment topology.  The fully-duplicated scenario commits
 * a separately lane-prefixed row/fold tree in each lane; it is slower and
 * larger than the shared-master default, but removes the shared-row-root
 * premise from the lane-independence experiment.  This is an executable
 * protocol variant, not a formal soundness promotion.
 */
[[nodiscard]] Fri3AlgDualBatchCommitResult
Fri3AlgDualQ136BatchCommitForScenario(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    Fri3AlgDualCommitmentScenario scenario,
    uint64_t pow_grind_nonce = 0);
[[nodiscard]] Fri3AlgDualBatchCommitResult
Fri3AlgDualQ136BatchCommitStreamingShared(
    const std::vector<std::vector<Fp3>>& columns,
    const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);
[[nodiscard]] bool Fri3AlgDualQ136BatchVerify(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);
[[nodiscard]] bool Fri3AlgDualQ136BatchVerifyForScenario(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed,
    Fri3AlgDualCommitmentScenario scenario,
    std::string* why = nullptr);
[[nodiscard]] Fri3AlgDualTranscriptProgram
BuildFri3AlgDualQ136TranscriptProgram(
    const Fri3AlgDualBatchProof& proof);
[[nodiscard]] Fri3AlgDualTranscriptWitness
BuildFri3AlgDualQ136TranscriptWitness(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed);
[[nodiscard]] size_t
SerializeFri3AlgDualQ136BatchProof(
    const Fri3AlgDualBatchProof& proof,
    std::vector<unsigned char>& out);
[[nodiscard]] std::optional<Fri3AlgDualBatchProof>
DeserializeFri3AlgDualQ136BatchProof(
    const std::vector<unsigned char>& in);
[[nodiscard]] std::optional<size_t>
EstimateFri3AlgDualQ136BatchProofBytes(
    uint32_t batch_columns, uint32_t n_coeffs);

/**
 * Exact canonical V5 envelope size for a valid power-of-two coefficient
 * domain. The codec has fixed Q=128 per lane and a deterministic fold/path
 * shape, so this does not depend on witness values. Returns nullopt on an
 * unsupported shape or arithmetic overflow.
 */
[[nodiscard]] std::optional<size_t>
EstimateFri3AlgDualBatchProofBytes(
    uint32_t batch_columns, uint32_t n_coeffs);

enum class Fri3AlgDualCommitmentScenario : uint8_t {
    /** Two independently domain-separated Poseidon commitment trees. */
    FullyDuplicatedLaneCommitments = 0,
    /** One shared Poseidon master tree plus ordered SHA-derived child binds. */
    SharedMasterDerivedChildren = 1,
};

/**
 * Executable audit/ledger for the two commitment scenarios considered for the
 * Q128 backend. The selected shared-master construction avoids duplicating
 * the production row tree and makes master/child substitution fail closed.
 * It deliberately reports the still-open common-commitment hybrid and full
 * NIROP separation obligations rather than converting implementation evidence
 * into a soundness claim.
 */
struct Fri3AlgDualOracleHybridAssessment {
    Fri3AlgDualCommitmentScenario scenario{
        Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren};
    uint32_t queries_per_lane{kRCFri3AlgDualQueriesPerLane};
    uint32_t total_queries{kRCFri3AlgDualTotalQueries};
    uint32_t batch_columns{0};
    uint32_t lde_log2{0};
    uint32_t independent_batch_draws_per_lane{0};
    uint32_t uniform_field_draws_per_lane{0};
    uint32_t sha_transcript_calls_per_lane{0};
    uint32_t common_commitment_collision_bits{
        kRCFri3AlgDualAlgHashCollisionBits};
    uint32_t global_site_log2{0};
    /** Standalone binding-event floor only. It is not the total protocol
     * soundness: callers must add the FRI error probability before comparing
     * the result with a deployment target. */
    uint32_t common_commitment_union_floor_bits{0};
    bool executable{false};
    bool independent_batching_executable{false};
    bool all_sha_transcript_calls_lane_prefixed{false};
    bool master_statement_binding_executable{false};
    bool ordered_child_binding_executable{false};
    bool duplicates_poseidon_row_tree{false};
    bool all_poseidon_oracle_calls_lane_prefixed{false};
    bool common_commitment_hybrid_reduction_complete{false};
    bool full_nirop_oracle_separation_proven{false};
    bool formal_soundness_ready{false};
    std::string note;
};

[[nodiscard]] Fri3AlgDualOracleHybridAssessment AssessFri3AlgDualOracleHybrid(
    Fri3AlgDualCommitmentScenario scenario,
    uint32_t batch_columns,
    uint32_t lde_log2,
    uint32_t global_site_log2 = 28);

/**
 * Proximity-only repetition diagnostic:
 * floor(2·128·log2(32/17)) − 40 = 193. It is deliberately not exposed as a
 * security claim until the independence/BCS and global ledgers are complete.
 *
 * PR-89 sign convention (lemma-5 reconciliation): the −40 here is the
 * UNENFORCED-regrind DEDUCTION for the plain (untaxed) dual-Q136 diagnostic —
 * the same distinct quantity as kRCFri3AlgUnenforcedRegrindBudgetBits, NOT the
 * +g enforced-tax credit. The taxed Π_JQ path scores +g via
 * Fri3AlgHonestDualFloorBits (credit sourced from Fri3AlgCheckSqueezeGrind in
 * Fri3AlgJointQBatchVerify); the two never contradict because they belong to
 * different (untaxed vs taxed) paths.
 */
[[nodiscard]] inline int Fri3AlgDualProximityBoundBits()
{
    constexpr uint64_t kLog2_32_17_Q32 = 3919317253ull;
    const uint64_t prod = static_cast<uint64_t>(kRCFri3AlgDualNumLanes) *
                          kRCFri3AlgDualQueriesPerLane * kLog2_32_17_Q32;
    return static_cast<int>(prod >> 32) - static_cast<int>(kRCFriGrindingBits);
}

[[nodiscard]] inline int
Fri3AlgDualQ136ProximityBoundBits()
{
    constexpr uint64_t kLog2_32_17_Q32 =
        3919317253ull;
    const uint64_t prod =
        static_cast<uint64_t>(
            kRCFri3AlgDualNumLanes) *
        kRCFri3AlgDualQ136QueriesPerLane *
        kLog2_32_17_Q32;
    return static_cast<int>(prod >> 32) -
           static_cast<int>(kRCFriGrindingBits);
}

/**
 * Internal proximity-parameter guard only. A true result does not establish
 * global or Fiat-Shamir soundness: the formal |L|^2/|Fp3| term, recursive-site
 * composition, batching, and random-oracle reductions are accounted by the
 * fail-closed Stage-3 soundness ledger.
 */
[[nodiscard]] inline bool Fri3AlgClaimedBitsMeetTarget()
{
    return Fri3AlgSoundnessBoundBits() >= kRCFri3AlgTargetSoundnessBits &&
           kRCFri3AlgNumQueries == 192u && kRCFriBlowup == 16u &&
           kRCFriGrindingBits == 40u && !kRCFriConjecturedBoundEnabled;
}

// ============================================================================
// PR-89 ENFORCEABLE SOUNDNESS CONSTRUCTIONS (permitted hard-fork changes).
//
// The shipped grinding term g=40 (kRCFriGrindingBits) is ABSORBED into the FS
// transcript but NEVER predicated: no leading-zero check exists, so it costs an
// adversary nothing and the honest floor is sub-64 (101.77 - q). These two
// additive constructions make the floor enforceable:
//
//  (1) Pi_JQ — JOINT QUERY SQUEEZE. A new dual-lane suite reusing
//      SharedMasterDerivedChildren. Both lanes run through the terminal fold;
//      the single deciding squeeze sigma_Q binds BOTH lanes' terminal
//      transcripts T_0,T_1, so a per-lane last-round regrind cannot retarget
//      one lane's query indices independently. Proof bytes identical to Q136.
//
//  (2) ENFORCED PER-SQUEEZE GRINDING TAX. A VERIFIER-CHECKED predicate: at a
//      taxed squeeze, SHA256d(squeeze-input || nonce) must have g leading zero
//      bits. One verifier hash; multiplies every grind attempt at that round by
//      2^g under NO adversary-budget assumption. Fused into Pi_JQ's deciding
//      squeeze here (the query-deriving hash IS the taxed hash).
//
// Neither flips a *_FormalSoundnessReady flag: >=100 still needs wider digests
// and per-round field bounds. They are enforceable parameter screens only.
// ============================================================================

inline constexpr char kRCFri3AlgJointQEnvelopeDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_JOINTQ_V1";
inline constexpr char kRCFri3AlgJointQQueryTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_JOINTQ_QUERY_V1";
inline constexpr char kRCFri3AlgJointQMasterBindingDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_JOINTQ_MASTER_BINDING_V1";
inline constexpr char kRCFri3AlgJointQChildBindingDomainTag[] =
    "BTX_RC_FRIB3ALG_DUAL_Q136_JOINTQ_CHILD_BINDING_V1";
inline constexpr uint32_t kRCFri3AlgJointQProofMagic = 0x51544a41u; // 'AJTQ'
inline constexpr uint32_t kRCFri3AlgJointQProofVersion = 1;
/** Default aggregate grinding target g for the taxed joint-query squeeze. */
inline constexpr uint32_t kRCFri3AlgJointQGrindBits = 40;
inline constexpr bool kRCFri3AlgJointQFormalSoundnessReady = false;
static_assert(!kRCFri3AlgJointQFormalSoundnessReady);

// --- Construction 2: enforced per-squeeze grinding tax primitives ---
/** Leading zero bits of a 32-byte digest, scanning bytes 0..31 MSB-first. */
[[nodiscard]] uint32_t Fri3AlgLeadingZeroBits(const uint256& digest);
/** SHA256d(squeeze_input || LE64(nonce)) — the taxed squeeze output. */
[[nodiscard]] uint256 Fri3AlgSqueezeGrindDigest(
    const std::vector<unsigned char>& squeeze_input, uint64_t nonce);
/** Verifier predicate: one hash, true iff the taxed squeeze has >= g leading
 *  zero bits. g==0 is always satisfied. */
[[nodiscard]] bool Fri3AlgCheckSqueezeGrind(
    const std::vector<unsigned char>& squeeze_input, uint64_t nonce, uint32_t g);
/** Slack over the 2^g expected trials used when max_iters is auto-derived.
 *  2^(g+10) leaves P(exhaust) = exp(-1024): unreachable in practice. */
inline constexpr uint32_t kGrindIterationSlackBits = 10;
/** Largest g the PROVER will attempt. Beyond this no honest prover completes,
 *  so Fri3AlgGrindSqueeze fails fast instead of spinning. This is a prover-side
 *  feasibility bound ONLY — Fri3AlgCheckSqueezeGrind still enforces any
 *  g <= 256, so a taxed path can never be weakened by this constant. */
inline constexpr uint32_t kRCFri3AlgMaxGrindableBits = 48;
static_assert(kRCFri3AlgMaxGrindableBits + kGrindIterationSlackBits < 64,
              "auto-derived grind budget must not overflow uint64_t");
static_assert(kRCFri3AlgJointQGrindBits <= kRCFri3AlgMaxGrindableBits,
              "the advertised Pi_JQ grind target must be prover-feasible");

/** Prover grind loop: smallest nonce in [0,max_iters) meeting the g-bit
 *  predicate, or nullopt if exhausted. max_iters == 0 (the default) derives the
 *  bound from g as 2^(g+kGrindIterationSlackBits); a flat default here is a bug
 *  because it silently under-runs whenever the shipped g exceeds it. */
[[nodiscard]] std::optional<uint64_t> Fri3AlgGrindSqueeze(
    const std::vector<unsigned char>& squeeze_input, uint32_t g,
    uint64_t max_iters = 0);

// ---------------------------------------------------------------------------
// PR-89 Construction 2, FIELD-NATIVE (Poseidon2) difficulty predicate.
//
// The SHA256d predicate above counts LEADING zero bits of a byte string. That
// is not well defined on a Goldilocks lane, so the algebraic transcript uses
// the TRAILING-zero form instead:
//
//     satisfied  <=>  Canonical(lane0) == 0 (mod 2^g)
//
// MEASURED bias for uniform x in [0,p), p = 2^64 - 2^32 + 1: the relative
// deviation of P[x = 0 mod 2^20] from 2^-20 is +5.7e-14. The leading-zero
// analogue is +2.3e-10. Both are negligible; the trailing form is also far
// cheaper to arithmetise, because only the low g bits are constrained.
//
// !!! VACUITY TRAP — DO NOT "OPTIMISE" THIS TO THE MULTIPLICATIVE FORM !!!
// The tempting one-constraint encoding is  lane0 == 2^g * h  for a witness h.
// Over Fp that constraint is COMPLETELY VACUOUS: 2^g is a UNIT, so
// h = lane0 * 2^-g exists for EVERY lane0 and the constraint is satisfied by
// every digest. It would look like a working tax, cost one constraint, and
// enforce NOTHING. The predicate must go through an explicit bit decomposition
// WITH the canonicity check on the recomposed 64-bit integer: without
// canonicity a prover may present B = x + p (only possible for x < 2^32 - 1),
// whose low bits differ from x's, and thereby claim the tax on a digest that
// does not satisfy it. Both failures are covered by unit tests; see
// pr89_algebraic_grind_predicate_is_not_vacuous.
// ---------------------------------------------------------------------------

/** Trailing zero bits of the canonical representative of an Fp lane.
 *  Returns 64 for zero (every bit position is a trailing zero). */
[[nodiscard]] uint32_t Fri3AlgTrailingZeroBitsFp(Fp x);

/** Largest g the FIELD-NATIVE predicate accepts. Above 63 the only satisfying
 *  lane is 0 itself (p < 2^64), which is a 2^-64 event, not a 2^-g tax. */
inline constexpr uint32_t kRCFri3AlgMaxAlgebraicGrindBits = 63;

/** Verifier predicate, field-native: true iff lane0 == 0 (mod 2^g).
 *  g == 0 is vacuously true, exactly as in the SHA256d form — a taxed path
 *  MUST static_assert a nonzero g of its own. */
[[nodiscard]] bool Fri3AlgCheckAlgebraicGrind(Fp lane0, uint32_t g);

/** Built AIR shape for the field-native predicate, plus the number of
 *  constraints the supplied lane value actually VIOLATES. `violations == 0`
 *  iff the value satisfies the tax AND its decomposition is canonical, so a
 *  test can observe rejection directly rather than trusting the shape. */
struct Fri3AlgGrindPredicateAirV1 {
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint32_t bit_columns{0};
    uint32_t tax_bits{0};
    uint32_t max_alg_degree{0};
    uint32_t violations{0};
    bool booleanity_constrained{false};
    bool canonicity_constrained{false};
    bool tax_constrained{false};
    bool valid{false};
    std::string note;
};

/** Build the predicate constraint system and evaluate it on `lane0`.
 *  `honest_bits` selects whether the witness is the true canonical
 *  decomposition of lane0 (false) or the NON-canonical aliased form B = x + p
 *  (true), which is the decomposition an attacker would supply to fake the
 *  tax. The canonicity constraints must reject the latter. */
[[nodiscard]] Fri3AlgGrindPredicateAirV1 BuildFri3AlgGrindPredicateAirV1(
    Fp lane0, uint32_t g, bool use_aliased_witness = false);

// ---------------------------------------------------------------------------
// PR-89 Construction 2, ALGEBRAIC taxed deciding squeeze (NOT ACTIVATED).
//
// This is the field-native counterpart of Fri3AlgJointQ*'s SHA256d squeeze, for
// ONE lane. Nothing in the shipped Q192 V3 path calls it; it carries its own
// domain tag and proof version so it cannot collide with a live transcript.
//
// Separability (settled): Pi_JQ's DUAL-lane binding defends against CROSS-LANE
// independent retargeting — moving lane 1's indices while lane 0's stay put.
// That attack exists only because there are two lanes. Construction 2 defends
// against retargeting the index vector AT ALL, by pricing every distinct sigma
// at 2^g. The two are orthogonal, so the tax is sound single-lane.
//
// The SOLE-ENTROPY-SOURCE obligation: sigma must be the only source of every
// query index. If any index could be resampled without moving sigma, an
// adversary would pay the tax ONCE and then retarget that index freely, and the
// credit would collapse from per-attempt to per-session.
// ---------------------------------------------------------------------------

/** Domain separator for the algebraic single-lane taxed squeeze. */
inline constexpr uint64_t kRCFri3AlgTaxedQDomain = 0x54415845'44513100ull; // "TAXEDQ1"
/** Domain separator for the per-index derivation off the taxed squeeze. */
inline constexpr uint64_t kRCFri3AlgTaxedQIndexDomain =
    0x54415845'44514958ull; // "TAXEDQIX"
/** Shipped tax for the algebraic single-lane suite. OWNER DECISION: g = 20 —
 *  ~0.5 s of honest prover grind, versus ~10 CPU-hours at g = 40. */
inline constexpr uint32_t kRCFri3AlgTaxedQGrindBits = 20;
static_assert(kRCFri3AlgTaxedQGrindBits > 0,
              "a taxed path must fix a NONZERO g: Fri3AlgCheckAlgebraicGrind "
              "is vacuously true at g == 0, so a zero here silently removes "
              "the entire tax while leaving the indices sigma-derived");
static_assert(kRCFri3AlgTaxedQGrindBits <= kRCFri3AlgMaxAlgebraicGrindBits);
static_assert(kRCFri3AlgTaxedQGrindBits <= kRCFri3AlgMaxGrindableBits,
              "the shipped tax must be prover-feasible");

/** Poseidon2 sponge digest of an Fp lane sequence under a domain separator. */
[[nodiscard]] Fri3AlgDigest Fri3AlgAlgebraicTranscriptDigest(
    const std::vector<Fp>& lanes, uint64_t domain);

/** The taxed deciding squeeze: sigma = Poseidon2(domain, sigma_core, nonce).
 *  The squeeze that DERIVES the indices IS the squeeze that is taxed — if the
 *  nonce did not enter here the tax would be pure cost and buy nothing. */
[[nodiscard]] Fri3AlgDigest Fri3AlgAlgebraicSqueeze(
    const std::vector<Fp>& sigma_core, uint64_t nonce);

/** Verifier side: one sponge call plus the field-native predicate on lane 0. */
[[nodiscard]] bool Fri3AlgCheckAlgebraicSqueezeGrind(
    const std::vector<Fp>& sigma_core, uint64_t nonce, uint32_t g);

/** Prover grind. max_iters == 0 derives 2^(g+kGrindIterationSlackBits). */
[[nodiscard]] std::optional<uint64_t> Fri3AlgGrindAlgebraicSqueeze(
    const std::vector<Fp>& sigma_core, uint32_t g, uint64_t max_iters = 0);

/** index_j = LE32(lane0 of Poseidon2(idx_domain, sigma, j)) & (n_lde - 1).
 *  n_lde MUST be a power of two so the mask is exactly uniform. Mirrors
 *  Fri3AlgJointQIndex's shape, so the in-AIR mask/bit-decomposition constraint
 *  system is UNCHANGED — only the digest preimage moves. */
[[nodiscard]] uint32_t Fri3AlgAlgebraicQueryIndex(const Fri3AlgDigest& sigma,
                                                  uint32_t j, uint32_t n_lde);

// ===========================================================================
// PR-89 g4, TRANSCRIPT HALF — SHORT SELF-CONTAINED FIAT-SHAMIR PREIMAGES.
// NOT ACTIVATED: carries its OWN proof version and domain tag; the shipped
// Q192 V3 lane (kRCFri3AlgBatchProofVersion = 3) is byte-identical to before.
//
// THE PROBLEM THIS SOLVES (measured; recursive_parent_air.h
// ChildFsReplayClosureV1 carries the same figures).  Every challenge on the
// shipped lane is ChallengeDigest(suffix) = SHA256d(buf || suffix) where `buf`
// is the WHOLE accumulated transcript, and `buf` contains two W-proportional
// terms:
//   (i)  4*W  bytes, the per-column `column_len` loop absorbed in
//        Fri3AlgBatchFsInit — at FS INIT, so it precedes EVERY challenge
//        including the very first;
//   (ii) 48*W bytes, both full OOD evaluation vectors (2*W Fp3 at 24 B) —
//        precedes w1/w2, every fold beta and every query index.
// Replaying one challenge in the parent's AIR therefore costs
// next_pow2(ceil((52*W + 9)/64) + 1) * 1024 rows: 5.37e8 rows per challenge at
// the real child width W = 384,984.  BOTH terms must go: committing only (ii)
// buys ~13x and leaves ~8,000x above the airq_lambda baseline.
//
// THE FIX.  Absorb a domain-tagged Poseidon2 COMMITMENT over the same data
// instead of the data.  The commitment reuses alg_hash::SpongeHashFp — the
// SAME primitive that is already this backend's Merkle hash — so no new
// cryptographic assumption is introduced, and its in-AIR replay is the
// Poseidon2 companion CS that the parent lane is already building.
//
// SOUNDNESS (full argument at the definition site in the .cpp).  Absorbing
// Commit(E) instead of E preserves EXACTLY the property the shipped
// transcript provides — every post-claim challenge is a function of the whole
// claim vector — up to a Poseidon2 collision, floor 2^128 (capacity 4;
// alg_hash::BindingEffectiveCollisionFloorBits).  Do NOT substitute the
// batched values v1,v2: that is a rank-2 LOSSY image of a 2W-dimensional
// claim space whose kernel is computable in closed form
// (matmul_v4_rc_fri_ext3_alg_order_audit.h:16-35).
// ===========================================================================

// kRCFri3AlgShortFsLaneProofVersion / kRCFri3AlgShortFsDomainTag and the
// kRCFri3AlgActive* selectors are declared at the TOP of this header, beside
// kRCFri3AlgBatchProofVersion, because Fri3AlgBatchProof's default member
// initializer and several early shape helpers need them.

/** Poseidon2 domain separators (ASCII, LE-packed) for the new preimages.
 *  Each enters SpongeHashFp as TWO 32-bit lanes via the same
 *  Fri3AlgAlgebraicTranscriptDigest wrapper the taxed squeeze uses, so
 *  domain separation is by injective prefix, not by lane truncation. */
inline constexpr uint64_t kRCFri3AlgShapeCommitDomain =
    0x53484150'45433100ull; // "SHAPEC1"
inline constexpr uint64_t kRCFri3AlgOodEvalCommitDomain =
    0x4F4F4445'56433100ull; // "OODEVC1"
inline constexpr uint64_t kRCFri3AlgSigmaCoreDomain =
    0x53494743'4F524500ull; // "SIGCORE"
inline constexpr uint64_t kRCFri3AlgAlgebraicFp3DrawDomain =
    0x46503344'52415700ull; // "FP3DRAW"
/** Domain for the P2-squeeze lane's ChallengeDigest replacement. */
inline constexpr uint64_t kRCFri3AlgP2SqueezeDrawDomain =
    0x50325351'5A445257ull; // "P2SQZDRW"

/**
 * Poseidon2 squeeze over a Fri3AlgFs byte buffer — the challenge function of
 * the P2-squeeze lane.  Packs `buf` as length-prefixed 32-bit LE lanes (same
 * injectivity discipline as aq::AirChallengeP2Lanes), appends the label bytes
 * and idx, and returns three canonical sponge lanes as Fp3.
 */
[[nodiscard]] Fp3 Fri3AlgP2SqueezeChallengeFp3(
    const std::vector<unsigned char>& buf, const char* label, uint32_t idx);

/** Full sponge absorb lane vector for Fri3AlgP2SqueezeChallengeFp3 — domain
 *  separator (two 32-bit lanes) then length-prefixed buf / label / idx. An
 *  in-AIR companion must absorb EXACTLY these lanes. */
[[nodiscard]] std::vector<gkr_field::Fp> Fri3AlgP2SqueezeAbsorbLanes(
    const std::vector<unsigned char>& buf, const char* label, uint32_t idx);

/**
 * Commitment to the child's SHAPE vector, replacing the 4*W-byte column_len
 * loop at FS init.  Lanes: W, n_coeffs, then column_len[0..W).  Every value is
 * < 2^32 so each occupies one Goldilocks lane injectively; SpongeHashFp's
 * 10*-padding makes the whole lane sequence injective, so the leading W also
 * pins the split.
 */
[[nodiscard]] Fri3AlgDigest Fri3AlgShapeCommit(
    uint32_t n_coeffs, const std::vector<uint32_t>& column_len);

/**
 * Commitment to BOTH full OOD evaluation vectors, replacing the 48*W bytes of
 * AbsorbFp3.  Lanes: W, z1(c0,c1,c2), z2(c0,c1,c2), then for i in [0,W) the
 * six lanes evals_z1[i], evals_z2[i].  z1/z2 are included even though they are
 * absorbed separately — it costs six lanes and makes the commitment bind the
 * (point, claim) PAIR rather than a bare claim vector.
 */
[[nodiscard]] Fri3AlgDigest Fri3AlgOodEvalCommit(
    const Fp3& z1, const Fp3& z2,
    const std::vector<Fp3>& evals_z1,
    const std::vector<Fp3>& evals_z2);

/**
 * sigma_core for Construction 2 — THE MISSING DEFINITION.
 *
 * Fri3AlgAlgebraicSqueeze / Fri3AlgAlgebraicQueryIndex take sigma as an INPUT
 * and no sigma_core was defined anywhere in the tree, so the mechanism had no
 * protocol-side producer and the only callers were unit tests passing literal
 * vectors.  This is that producer: the Goldilocks-lane encoding of the child's
 * transcript AT THE TERMINAL FOLD, i.e. every message the child committed
 * before the first query index is drawn.
 *
 * Lane layout (all multi-byte scalars split into 32-bit halves by
 * AppendU64Lanes so no two distinct values alias onto one Goldilocks lane):
 *   proof_version | fs_seed (8) | pow_grind_nonce (2) | blowup | n_coeffs |
 *   W | row_commit.root (4) | shape_commit (4) | ood_eval_commit (4) |
 *   lambda (3) | z1 (3) | z2 (3) | w1 (3) | w2 (3) |
 *   for each fold layer: n_leaves | root (4);
 *   for each fold challenge: beta (3);
 *   final_value (3)
 * Length is O(log n_coeffs), NOT O(W): 133 lanes at n_coeffs = 2048.
 *
 * VERIFIER-DERIVABLE, and only sound because of that.  Every field read here
 * is one the verifier has ALREADY re-derived from its own FS replay and
 * compared (lambda, z1, z2, w1, w2, fold betas) or is a commitment it checks
 * (row root, fold roots, final constant layer).  Calling this on a proof whose
 * FS replay has not yet been checked binds nothing.
 *
 * SOLE-ENTROPY-SOURCE obligation (fri_ext3_alg.h, Construction 2): sigma must
 * be the only source of every query index.  It is, on this lane: the query
 * loop draws no transcript challenge, and every input above is fixed by the
 * fold phase, so moving any index requires moving sigma and paying the tax
 * again.
 */
[[nodiscard]] std::vector<Fp> Fri3AlgAlgebraicSigmaCore(
    const uint256& fs_seed, const Fri3AlgBatchProof& proof);

/** Which challenge the algebraic Fp3 draw is producing. The kind enters the
 *  preimage as its own lane, so two kinds at the same index cannot collide. */
enum class Fri3AlgAlgebraicDrawKind : uint32_t {
    Lambda = 1, // fra3_lambda / fra3_batch_coeff
    Ood = 2,    // fra3_z
    Weight = 3, // fra3_w
    Fold = 4,   // fra3_fold
};

/**
 * ALGEBRAIC Fp3 challenge draw — the primitive fri_ext3_alg.h did not export.
 * Without it fra3_lambda, fra3_z x2, fra3_w x2 and fra3_fold cannot leave
 * SHA, and the algebraic query-index rule covers 1 of 8 challenge kinds.
 *
 *   draw = (d[0], d[1], d[2]) where
 *   d = Poseidon2(kRCFri3AlgAlgebraicFp3DrawDomain, core, kind, idx)
 *
 * EXACTLY UNIFORM WITH NO REJECTION SAMPLER.  A Poseidon2 output lane is a
 * Goldilocks field element by construction, so the three lanes are already
 * uniform on Fp^3 under the same permutation-is-ideal assumption the Merkle
 * tree makes.  The SHA route has to draw eight 64-bit words and reject the
 * non-canonical ones (Fri3AlgSelectUniformFp3Words, two hash blocks, a
 * binomial failure tail the global ledger charges); none of that survives
 * here.  That removes a failure mode as well as a cost.
 */
[[nodiscard]] Fp3 Fri3AlgAlgebraicChallengeFp3(
    const std::vector<Fp>& core, Fri3AlgAlgebraicDrawKind kind, uint32_t idx);

/**
 * MEASURED transcript-length and in-AIR replay cost, per challenge kind.
 *
 * `*_prefix_bytes` are read off a REAL Fri3AlgFs buffer built by the real
 * prover at the given width — not modelled.  The SHA row figures use the
 * shipped vertical SHA AIR schedule (hash_air.cpp
 * BuildFixedProgramVerticalWitnessBoundaryInstance:
 * n_rows = next_pow2(compressions) * 1024, LANE_ROWS = 1024), the same formula
 * stage3_fs_selection_air::MeasureAlgebraicQueryIndexReplayCostV1 uses, so the
 * two are directly comparable.
 */
struct Fri3AlgTranscriptChallengeCostV1 {
    /** "fra3_lambda", "fra3_z", "fra3_w", "fra3_fold", "fra3_query". */
    std::string label;
    /** fs.buf.size() immediately before this challenge's ChallengeDigest. */
    uint64_t prefix_bytes{0};
    uint64_t compressions{0};
    uint64_t rows{0};
};

struct Fri3AlgTranscriptReplayCostV1 {
    uint32_t child_w{0};
    uint32_t n_coeffs{0};
    uint32_t queries{0};
    /** One entry per DISTINCT challenge kind, at its FIRST occurrence. */
    std::vector<Fri3AlgTranscriptChallengeCostV1> legacy;
    std::vector<Fri3AlgTranscriptChallengeCostV1> short_fs;
    /** Sum over every challenge actually drawn (all kinds, all indices). */
    uint64_t legacy_total_rows{0};
    uint64_t short_fs_total_rows{0};
    /** Widest single-challenge cost on each route. */
    uint64_t legacy_max_rows{0};
    uint64_t short_fs_max_rows{0};
    bool short_fs_width_independent{false};
    bool valid{false};
    std::string note;
};

/** Run BOTH lanes at `child_w` columns of `column_len` coefficients each and
 *  report the measured transcript lengths. Small widths only — this runs the
 *  real prover twice. */
[[nodiscard]] Fri3AlgTranscriptReplayCostV1
MeasureFri3AlgTranscriptReplayCostV1(uint32_t child_w, uint32_t column_len);

/** LEGACY V3 lane commit/verify, exported ONLY so the A/B that isolates the
 *  transcript layout still has a producer after activation.
 *
 *  Before activation the A/B was Fri3AlgBatchCommit (V3) vs
 *  Fri3AlgShortFsBatchCommit (V7).  Activation makes Fri3AlgBatchCommit the V7
 *  lane, which would have left the V3 arm of that comparison with no producer
 *  at all -- i.e. the evidence that the two layouts are distinguishable would
 *  have quietly stopped being computed.  Nothing on any consensus path selects
 *  these; they exist so the comparison keeps being MEASURED. */
[[nodiscard]] Fri3AlgBatchCommitResult Fri3AlgLegacyV3BatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);
[[nodiscard]] bool Fri3AlgLegacyV3BatchVerify(
    const Fri3AlgBatchProof& proof, const uint256& fs_seed,
    std::string* why = nullptr);

/** Short-transcript lane commit/verify. Same statement, same Q=192, same
 *  proximity guard; only the FS preimage layout and the version/tag move. */
[[nodiscard]] Fri3AlgBatchCommitResult Fri3AlgShortFsBatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);
[[nodiscard]] bool Fri3AlgShortFsBatchVerify(
    const Fri3AlgBatchProof& proof, const uint256& fs_seed,
    std::string* why = nullptr);

/** P2-squeeze lane commit/verify (version 8). Short-FS absorbs + Poseidon2
 *  challenge squeezes. Not selected by Fri3AlgBatchCommit until
 *  kRCFri3AlgP2SqueezeActivatedV1. */
[[nodiscard]] Fri3AlgBatchCommitResult Fri3AlgP2SqueezeBatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);
[[nodiscard]] bool Fri3AlgP2SqueezeBatchVerify(
    const Fri3AlgBatchProof& proof, const uint256& fs_seed,
    std::string* why = nullptr);

/**
 * SHA-FS digest-match canary commit (NOT consensus / NOT Fri3AlgBatchCommit).
 *
 * Same absorb layout as the active P2-squeeze lane (version 8, short-FS
 * commitment lanes) but draws challenges via SHA256d and samples z1/z2 from a
 * fixed K=2 OOD window. Lets BuildFiatShamirShaExecutionPlanV1 measure
 * every_digest_matches_claim on an honestly bounded-sampled proof while
 * production keeps Poseidon2 squeezes. Small query_count for light MemoryMax
 * canaries; do not treat as Q192 proximity evidence.
 */
[[nodiscard]] Fri3AlgBatchCommitResult Fri3AlgShaFsBoundedOodCanaryBatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0);

/** Built, executable and measurable; consumed by NO consensus path. Mirrors
 *  the kAlgebraicQueryIndexActivatedV1 precedent in fs_selection_air. */
inline constexpr bool kRCFri3AlgShortFsExecutableV1 = true;
static_assert(kRCFri3AlgShortFsLaneProofVersion != kRCFri3AlgBatchProofVersion &&
                  kRCFri3AlgShortFsLaneProofVersion !=
                      kRCFri3AlgDualLaneProofVersion &&
                  kRCFri3AlgShortFsLaneProofVersion !=
                      kRCFri3AlgDualQ136LaneProofVersion,
              "a new FS layout MUST NOT reuse a live lane's proof version");
static_assert(kRCFri3AlgP2SqueezeLaneProofVersion !=
                      kRCFri3AlgDualLaneProofVersion &&
                  kRCFri3AlgP2SqueezeLaneProofVersion !=
                      kRCFri3AlgDualQ136LaneProofVersion,
              "P2-squeeze proof version must not collide with dual lanes");

// --- Construction 1: Pi_JQ joint query squeeze ---
/** index_{l,j} = LE32(SHA256d(sigma_Q || "fra3_joint_query" || l || j)) &
 *  (n_lde-1). n_lde must be a power of two. */
[[nodiscard]] uint32_t Fri3AlgJointQIndex(const uint256& sigma_q, uint32_t lane,
                                          uint32_t j, uint32_t n_lde);

struct Fri3AlgJointQCommitResult {
    Fri3AlgDualBatchProof proof;
    /** Dedicated cheap tax nonce for the deciding squeeze (external metadata;
     *  not part of the byte-identical Q136 proof body). */
    uint64_t joint_query_grind_nonce{0};
    /** The taxed deciding squeeze that derives every lane's query indices. */
    uint256 joint_query_sigma{};
    uint32_t grind_bits{0};
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

/**
 * Build a Pi_JQ dual proof. Two prover passes: (1) run both lanes to the
 * terminal fold to capture T_0,T_1; (2) squeeze sigma_core, grind the cheap
 * per-squeeze tax nonce, form the taxed deciding squeeze sigma_Q and re-run
 * both lanes opening every query at the joint index. The master binding
 * absorbs sigma_Q. Proof bytes are identical to the Q136 codec.
 */
[[nodiscard]] Fri3AlgJointQCommitResult Fri3AlgJointQBatchCommit(
    const std::vector<std::vector<Fp3>>& columns, const uint256& fs_seed,
    uint64_t pow_grind_nonce = 0,
    uint32_t grind_bits = kRCFri3AlgJointQGrindBits);

/**
 * Verify a Pi_JQ dual proof. Replays both lanes to the terminal fold to
 * recompute T_0,T_1 and sigma_core, CHECKS the enforced g-bit tax on the
 * deciding squeeze (one hash), recomputes sigma_Q, then fully verifies each
 * lane with every query index bound to the joint derivation. Also checks the
 * sigma_Q-absorbing master/child bindings.
 */
[[nodiscard]] bool Fri3AlgJointQBatchVerify(
    const Fri3AlgDualBatchProof& proof, uint64_t joint_query_grind_nonce,
    const uint256& fs_seed, uint32_t grind_bits, std::string* why = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_ALG_H
