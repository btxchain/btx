// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_VERIFIER_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_VERIFIER_AIR_H

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_narrow_recurse.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace matmul::v4::rc::stage3_verifier_air {

using gkr_field::Fp3;
using narrow_recurse::NarrowChildShape;

/**
 * Fixed verifier-program rows. PoseidonPermutation and FiatShamirAbsorb are
 * deliberately separate from the scalar chip: the former is supplied by the
 * decomposed Poseidon AIR and the latter still needs the bit-level SHA256d
 * relation used by the frozen child transcript.
 */
enum class ProgramRowKind : uint8_t {
    PoseidonPermutation = 0,
    MerkleCompress = 1,
    FoldAlgebra = 2,
    DeepAccumulate = 3,
    PerPointAccumulate = 4,
    FiatShamirAbsorb = 5,
    Boundary = 6,
    Padding = 7,
};

enum class ProgramRowSource : uint8_t {
    RowLeaf = 0,
    RowMerkle = 1,
    FoldEvenLeaf = 2,
    FoldEvenMerkle = 3,
    FoldOddLeaf = 4,
    FoldOddMerkle = 5,
    FoldEquation = 6,
    DeepEquation = 7,
    PerPointEquation = 8,
    BoundaryEquation = 9,
    FiatShamirTranscript = 10,
    Padding = 11,
};

struct ProgramRow {
    ProgramRowKind kind{ProgramRowKind::Padding};
    ProgramRowSource source{ProgramRowSource::Padding};
    uint16_t child{0};
    uint16_t query{0};
    uint16_t layer{0};
    uint32_t step{0};

    bool operator==(const ProgramRow&) const = default;
};

/**
 * Canonical, proof-independent schedule for one fixed-shape binary verifier.
 * rows includes power-of-two padding. active_rows exactly matches
 * BuildNarrowVcsPlan(...).active_rows for the fully-quadratic vertical lane.
 */
struct VerifierProgram {
    NarrowChildShape child_shape{};
    uint64_t active_rows{0};
    uint32_t trace_rows{0};
    std::vector<ProgramRow> rows;
    std::array<uint64_t, 8> row_kind_counts{};
    bool valid{false};
    std::string note;
};

[[nodiscard]] VerifierProgram
BuildCanonicalVerifierProgram(const NarrowChildShape& child);

/** Rejects omissions, insertions, reordering, metadata substitution and
 * non-canonical padding by rebuilding the fixed program. */
[[nodiscard]] bool ValidateCanonicalVerifierProgram(
    const VerifierProgram& program, std::string* why = nullptr);

enum class VerifierChildPacking : uint8_t {
    VerticalRows = 0,
    ParallelLanes = 1,
};

struct ExactVerifierScheduleScenario {
    VerifierChildPacking packing{VerifierChildPacking::VerticalRows};
    uint64_t non_fiat_shamir_rows_per_child{0};
    uint64_t fiat_shamir_rows_per_child{0};
    uint64_t naive_fiat_shamir_rows_per_child{0};
    uint64_t active_rows{0};
    uint32_t trace_rows{0};
    uint32_t width{0};
    uint32_t quotient_coeffs{0};
    uint32_t lde_rows{0};
    uint64_t cells{0};
    bool column_cap_met{false};
    bool lde_cap_met{false};
    bool backend_shape_supported{false};
    bool executable_layout{false};
    std::string note;
};

/**
 * Replaces the old sponge-word estimate with the exact byte-identical
 * streaming-prefix SHA256d schedule and compares vertical versus two-lane
 * child packing.  Both shapes fit the current backend after prefix sharing;
 * the physical ParallelLanes witness layout remains open.
 */
[[nodiscard]] std::vector<ExactVerifierScheduleScenario>
AssessExactVerifierScheduleScenarios(const NarrowChildShape& child);

enum class ScalarOp : uint8_t {
    MerkleRoute = 0,
    FoldAlgebra = 1,
    DeepAccumulate = 2,
    PerPointIdentity = 3,
    BoundaryEquality = 4,
    Count = 5,
};

inline constexpr uint32_t kScalarOpCount =
    static_cast<uint32_t>(ScalarOp::Count);

/**
 * One narrow scalar row. The four-lane fields are used by MerkleRoute:
 *
 *   left  = dir ? sibling : accumulator
 *   right = dir ? accumulator : sibling.
 *
 * The scalar fields carry:
 *   Fold:      (a,b,c,d,out)=(f(x),f(-x),x,beta,folded)
 *   DEEP/RLC:  out=a*b+c
 *   Per-point: a=b*c
 *   Boundary:  out=a.
 */
struct ScalarRowWitness {
    uint32_t program_row{0};
    ScalarOp op{ScalarOp::FoldAlgebra};
    std::array<Fp3, 4> accumulator{};
    std::array<Fp3, 4> sibling{};
    std::array<Fp3, 4> left{};
    std::array<Fp3, 4> right{};
    Fp3 a{};
    Fp3 b{};
    Fp3 c{};
    Fp3 d{};
    Fp3 out{};
    Fp3 direction{};
};

struct ScalarLayout {
    uint32_t accumulator_base{0};
    uint32_t sibling_base{4};
    uint32_t left_base{8};
    uint32_t right_base{12};
    uint32_t a{16};
    uint32_t b{17};
    uint32_t c{18};
    uint32_t d{19};
    uint32_t out{20};
    uint32_t direction{21};
    uint32_t selector_base{22};

    [[nodiscard]] uint32_t Selector(ScalarOp op) const
    {
        return selector_base + static_cast<uint32_t>(op);
    }
    [[nodiscard]] uint32_t End() const
    {
        return selector_base + kScalarOpCount;
    }
};

[[nodiscard]] constexpr ScalarLayout CanonicalScalarLayout()
{
    return {};
}

/** Selector-gated degree-three AIR for all non-hash verifier operations. */
[[nodiscard]] bool BuildVerifierScalarSystem(
    const VerifierProgram& program,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);

/**
 * Materialize columns from exact scalar rows. Exactly one row must be supplied
 * for every scalar-bearing program row, in program order. This routine does
 * not repair invalid arithmetic; an invalid witness produces an inexact
 * quotient and is rejected.
 */
[[nodiscard]] bool BuildVerifierScalarWitness(
    const VerifierProgram& program,
    const std::vector<ScalarRowWitness>& rows,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why = nullptr);

/** Deterministic honest scalar witness used for differential/mutation tests.
 * It is not a child-proof witness builder. */
[[nodiscard]] std::vector<ScalarRowWitness>
BuildDeterministicScalarWitness(const VerifierProgram& program);

[[nodiscard]] uint32_t CountVerifierScalarViolations(
    const air_quotient::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t* first_row = nullptr,
    std::string* first_constraint = nullptr);

enum class FiatShamirEventKind : uint8_t {
    AbsorbPreamble = 1,
    ChallengeLambda = 2,
    AbsorbLambda = 3,
    ChallengeZ1 = 4,
    ChallengeZ2 = 5,
    AbsorbZ1Z2 = 6,
    AbsorbOodEvaluationPair = 7,
    /** PR-89 g4 ACTIVATION.  Under the short-transcript lane the 48*W bytes of
     *  verbatim OOD-evaluation absorption are replaced by ONE 32-byte
     *  Poseidon2 commitment (Fri3AlgOodEvalCommit).  A distinct kind, not a
     *  re-indexed AbsorbOodEvaluationPair: the two absorb DIFFERENT bytes and
     *  a program that confuses them would replay a different transcript. */
    AbsorbOodEvalCommitment = 15,
    ChallengeW1 = 8,
    ChallengeW2 = 9,
    AbsorbW1W2 = 10,
    AbsorbFoldRoot = 11,
    ChallengeFold = 12,
    ChallengeQueryIndex = 13,
    ChallengeAirQuotientLambda = 14,
};

struct FiatShamirEventSpec {
    FiatShamirEventKind kind{};
    uint32_t index{0};
    uint64_t transcript_bytes_before{0};
    uint32_t absorbed_bytes{0};
    uint32_t minimum_sha256_compression_blocks{0};

    bool operator==(const FiatShamirEventSpec&) const = default;
};

// ---------------------------------------------------------------------------
// Bounded, fixed-schedule OOD (z1/z2) sampler bound.
//
// Fri3AlgBatchSampleZ rejects a draw z in Fp3 = Fp[x]/(x^3-2) when z lies on
// the base-field line (c1==0 && c2==0), i.e. z is in the LDE domain's ambient
// base field Fp and therefore is a candidate evaluation point rather than a
// genuine out-of-domain point; z2 additionally rejects z2==z1.  The bad set is
// exactly the |Fp| base-field elements out of |Fp|^3 total, so a uniform draw
// is rejected with probability |Fp|/|Fp|^3 = 1/p^2.  With Goldilocks
// p = 2^64 - 2^32 + 1 > 2^63 this is <= 2^-126 (exact value ~2^-127.9999999993).
//
// A statically-fixed schedule of K candidate draws with an in-circuit
// first-acceptable-index selector therefore fails (all K rejected) with
// probability <= 2^-(K * base_field_bits * ext_coords).  This is the
// field-independent construction: the SHA-FS chip lays all K SHA256d draws in
// a fixed-width V_CS and a selector picks the first candidate passing the
// predicate, giving rejection_loop_bounded with a proven negligible failure.
inline constexpr uint32_t kRCFiatShamirOodBaseFieldBits = 63;   // p > 2^63
inline constexpr uint32_t kRCFiatShamirOodExtCoords = 2;        // c1,c2 (Fp3)
inline constexpr uint32_t kRCFiatShamirOodTargetBits = 128;     // required margin
inline constexpr uint32_t kRCFiatShamirOodCandidateSchedule = 2; // K

struct FixedOodScheduleBound {
    uint32_t candidates_k{0};
    // Lower bound on -log2(per-draw rejection probability).
    uint32_t per_draw_reject_bits{0};
    // Lower bound on -log2(Pr[all K candidates rejected]).
    uint32_t all_rejected_bits{0};
    uint32_t target_bits{0};
    // True iff K>=1 (a statically-fixed number of draws) AND the all-rejected
    // failure probability is <= 2^-target_bits.
    bool bounded{false};
};

// candidates_k==0 models the legacy V3 unbounded while(true) sampler: it is
// never bounded regardless of the probability bound.  candidates_k>=1 models
// the fixed-schedule sampler.
[[nodiscard]] FixedOodScheduleBound ComputeFixedOodScheduleBound(
    uint32_t candidates_k,
    uint32_t base_field_bits = kRCFiatShamirOodBaseFieldBits,
    uint32_t ext_coords = kRCFiatShamirOodExtCoords,
    uint32_t target_bits = kRCFiatShamirOodTargetBits);

// Returns the index in [0,candidates.size()) of the first candidate passing the
// OOD predicate (off the base-field line, and != *distinct_from when non-null),
// or candidates.size() if every candidate is rejected (the negligible failure).
[[nodiscard]] uint32_t SelectFirstAcceptableOodIndex(
    const std::vector<Fp3>& candidates,
    const Fp3* distinct_from = nullptr);

/**
 * Exact accepted-event transcript for the legacy Q192/V3 Alg-FRI verifier.
 * z-rejection sampling is deliberately reported separately: the protocol has
 * no consensus maximum retry count, so this fixed program is not yet a
 * complete AIR for the rejection loop.  It must not be used as the executable
 * dual-Q128/V5 transcript: V5 has two lane seeds, independent per-column
 * coefficients, uniform two-hash draws and bounded two-candidate OOD sampling.
 */
struct FiatShamirProgram {
    NarrowChildShape child_shape{};
    // Exact child protocol identity. These fields are committed and
    // canonicalized so a bounded SHA canary program cannot be replayed
    // against the live Poseidon2 lane (or vice versa).
    uint32_t child_proof_version{0};
    std::string child_domain_tag;
    uint32_t child_domain_tag_bytes{0};
    bool child_short_transcript_commitments{false};
    bool child_sha256d_challenges{false};
    bool canary_only{false};
    bool authority_eligible{false};
    uint64_t scheduled_rows{0};
    uint64_t absorbed_bytes{0};
    /** Cost of independently rehashing the complete prefix per challenge. */
    uint64_t minimum_sha256_compression_blocks{0};
    /** Byte-identical cost with one shared streaming prefix midstate. */
    uint64_t streaming_sha256_compression_blocks{0};
    std::vector<FiatShamirEventSpec> events;
    uint256 commitment{};
    bool scheduler_capacity_sufficient{false};
    bool rejection_loop_bounded{false};
    // 0: legacy V3 unbounded single-draw OOD format.  >=1: fixed schedule of
    // this many candidate draws per OOD challenge (bounded format).
    uint32_t ood_candidates{0};
    bool valid{false};
    std::string note;
};

struct FiatShamirEventWitness {
    uint32_t event_index{0};
    std::vector<unsigned char> absorbed_payload;
    Fp3 claimed_challenge{};
    uint32_t claimed_query_index{0};
    bool has_fp3_challenge{false};
    bool has_query_index{false};

    bool operator==(const FiatShamirEventWitness& other) const
    {
        return event_index == other.event_index &&
               absorbed_payload == other.absorbed_payload &&
               claimed_challenge.c0 == other.claimed_challenge.c0 &&
               claimed_challenge.c1 == other.claimed_challenge.c1 &&
               claimed_challenge.c2 == other.claimed_challenge.c2 &&
               claimed_query_index == other.claimed_query_index &&
               has_fp3_challenge == other.has_fp3_challenge &&
               has_query_index == other.has_query_index;
    }
};

struct FiatShamirWitness {
    std::vector<FiatShamirEventWitness> events;
    uint256 program_commitment{};
    uint256 witness_commitment{};
    bool claims_bound_to_child_proof{false};
    bool sha256_equations_checked{false};
    bool valid{false};
    std::string note;
};

using AlgAirProof = air_quotient::AirQuotientProof<
    Fp3, air_quotient::AirFriBackendAlg<Fp3>>;

[[nodiscard]] FiatShamirProgram
BuildCanonicalFiatShamirProgram(const NarrowChildShape& child);
// Hard-fork bounded transcript format: schedules `ood_candidates` fixed
// candidate draws per OOD challenge (z1,z2) and flips rejection_loop_bounded
// when ComputeFixedOodScheduleBound proves negligible failure.  ood_candidates
// defaults to kRCFiatShamirOodCandidateSchedule.
[[nodiscard]] FiatShamirProgram BuildBoundedFiatShamirProgram(
    const NarrowChildShape& child,
    uint32_t ood_candidates = kRCFiatShamirOodCandidateSchedule);
[[nodiscard]] bool ValidateCanonicalFiatShamirProgram(
    const FiatShamirProgram& program, std::string* why = nullptr);
[[nodiscard]] FiatShamirWitness BuildFiatShamirWitness(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof);

/**
 * Reduced consensus-path variant of the Fiat-Shamir witness.
 *
 * For each COVERED challenge kind, the challenge value is RECONSTRUCTED in-AIR
 * from its SHA-derived digest words via the OOD selection decoder
 * (fs_selection_air::BuildWitnessV1, whose `selected_value` is constrained to
 * the first three accepted words) -- it is NOT copied from the proof batch.
 * The supplied 8 words per covered kind are those drawn from that challenge's
 * SHA transcript; Edge 2's committed CTL bus binds them to the committed SHA
 * output-bit cells, so the reconstructed challenge is a function of SHA(preimage)
 * with no host extraction.
 *
 * `covers_all_challenge_types` is the gate for the consensus
 * FiatShamirWitness::sha256_equations_checked: it is true only when EVERY
 * challenge kind is reconstructed here.  This V1 covers the OOD kinds (z1,z2)
 * that share the fully-built selection decoder; the direct-decode kinds
 * (airq-lambda, lambda, w1, w2, fold betas) use FromChallengeBytes3 and the
 * query-index decoder, each a per-kind SHA transcript -- a mechanical scale-up.
 */
/**
 * Per-kind reconstruction input.  Each covered challenge kind routes to its
 * in-AIR decoder: z1/z2 -> OOD selection (8 words); query-index -> query
 * decoder (4 bytes + power-of-two modulus); airq-lambda/lambda/w1/w2/fold-beta
 * -> direct byte->Fp3 decoder (24 bytes).  The supplied bytes/words are drawn
 * from that challenge's SHA transcript and are bound to the committed SHA
 * output cells by Edge 2's CTL bus.
 */
struct FiatShamirChallengeReconstructionInputV1 {
    FiatShamirEventKind kind{};
    // MultiRow-V2 uniform OOD decoder (8 LE words from two SHA256d digests).
    std::array<uint64_t, 8> ood_words{};
    // ChallengeFp3 / FromChallengeBytes3 map (24 SHA digest bytes). Used for
    // airq-lambda/lambda/w1/w2/fold, and for z1/z2 when ood_words are unused
    // (SHA-FS canary path; WitnessV1 when any ood_word is nonzero).
    std::array<unsigned char, 24> direct_bytes{};
    std::array<unsigned char, 4> query_bytes{}; // query-index
    uint32_t query_modulus{0};
};

struct FiatShamirAirBackedWitnessV1 {
    std::vector<FiatShamirEventKind> reconstructed_kinds;
    std::vector<Fp3> reconstructed_values; // AIR-derived, not batch-copied
    uint32_t reconstructed_challenge_types{0};
    uint32_t total_challenge_types{0};
    bool all_covered_reconstructions_constrained{false};
    bool covers_all_challenge_types{false};
    bool challenge_decoders_checked{false};
    // True iff covers_all_challenge_types: EVERY challenge kind's
    // challenge-to-output map is reconstructed in-AIR here (each decoder's
    // constraint system has zero violations).  The other half of the property
    // -- the SHA compression equations and the CTL binding of these decoder
    // inputs to the committed SHA output cells -- is established at reduced
    // shape by the unification / Edge-2 CTL tests (which build real SHA
    // instances); this variant consumes those SHA-derived inputs rather than
    // rebuilding a SHA instance per kind (the full-shape per-kind instances are
    // the GPU-run scale-up).  This is the AIR-backed analog of the consensus
    // FiatShamirWitness::sha256_equations_checked; the host-copy
    // BuildFiatShamirWitness keeps ITS sha256_equations_checked false.
    // Decoder constraints do not prove the upstream SHA/Poseidon
    // permutation. This remains false until those proof-owned output cells
    // are equality-linked to the decoder inputs in the same recursive proof.
    bool sha256_equations_checked{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] FiatShamirAirBackedWitnessV1
BuildFiatShamirAirBackedWitnessV1(
    const std::vector<FiatShamirChallengeReconstructionInputV1>&
        inputs);

/**
 * Host-side differential replay of the authoritative child transcript.
 *
 * This does not merely compare a commitment to proof-carried challenges:
 * Fri3AlgBatchVerify independently reconstructs every FRI challenge and query
 * index from child_fs_seed and rejects any mismatch.  The AIR quotient
 * challenge is reconstructed independently as well.  The result is useful to
 * test/build a whole-verifier witness, but does not claim that the SHA256d
 * equations are represented inside V_CS.
 */
struct FiatShamirReplayResult {
    uint64_t absorbed_bytes{0};
    uint64_t minimum_sha256_compression_blocks{0};
    uint64_t streaming_sha256_compression_blocks{0};
    uint32_t event_count{0};
    bool canonical_program{false};
    bool witness_matches_proof{false};
    bool air_quotient_challenge_replayed{false};
    bool fri_transcript_replayed{false};
    bool rejection_loop_bounded{false};
    bool complete_for_recursive_air{false};
    std::string note;
};

enum class FiatShamirShaByteOriginKindV1 : uint8_t {
    Constant = 0,
    PublicSeed = 1,
    BatchCodec = 2,
    SupplementalTraceCommit = 3,
    // Edge 1: a transcript-seed byte whose value is OWNED-BY the parent's
    // AlgHash binding-sponge digest h_cj (the canonical little-endian-limb
    // packing of a Goldilocks digest, realized by Fri3AlgDigestToUint256).
    // Distinct from PublicSeed: the 32 seed bytes are not caller-arbitrary but
    // bound by equality to the parent's binding of the child statement.
    ParentBindingDigest = 4,
    // PR-89 g4 ACTIVATION.  A transcript byte that is NOT a verbatim slice of
    // the child's serialized batch proof but a lane of a Poseidon2 commitment
    // OVER a region of it (Fri3AlgShapeCommit / Fri3AlgOodEvalCommit).
    //
    // This kind exists because short-FS BREAKS the invariant the other four
    // kinds encode -- "every absorbed byte is a constant, the seed, or a byte
    // the child shipped".  Discharging it needs an in-AIR Poseidon2 sponge
    // over the named region; a SHA-only companion CANNOT own these bytes.
    // Recording them as Constant or BatchCodec would be a LIE that type-checks.
    AlgebraicShapeCommitment = 5,
    AlgebraicOodEvalCommitment = 6,
};

struct FiatShamirShaByteOriginV1 {
    FiatShamirShaByteOriginKindV1 kind{
        FiatShamirShaByteOriginKindV1::Constant};
    uint32_t byte_offset{0};
    bool operator==(
        const FiatShamirShaByteOriginV1&) const =
        default;
};

struct FiatShamirShaCallV1 {
    uint32_t event_index{0};
    uint32_t draw_index{0};
    std::vector<unsigned char> preimage;
    std::vector<FiatShamirShaByteOriginV1>
        byte_origins;
    uint256 digest{};
    bool output_matches_claim{false};
};

/**
 * Edge 1 — cross-module Fiat–Shamir SEED OWNERSHIP BUS.
 *
 * The child transcript's 32-byte seed (a SHA256d preimage input, see
 * AbsorbPreamble) and the parent's AlgHash binding-sponge digest h_cj live in
 * two different constraint systems over two different fields: SHA-preimage
 * bytes vs Goldilocks Fp limbs.  The ONLY sound byte boundary between them is
 * the canonical little-endian-limb packing
 *   seed[8k, 8k+8) = LE64(Canonical(limb_k)),  k = 0..3
 * realized by Fri3AlgDigestToUint256 (a bijection on canonical digests;
 * Fri3AlgDigestFromUint256 rejects any limb >= p, so the image is unforgeable).
 *
 * This bus materializes that packing as the parent-OWNED seed image, tags all
 * 32 seed bytes with the ParentBindingDigest byte-origin, and exposes an
 * equality predicate (FiatShamirSeedBusViolations) so a caller can decide
 * whether an independently supplied seed is genuinely equal to — owned by —
 * the parent binding digest.  Because the packing is injective, changing ANY
 * limb of h_cj changes the owned seed image and therefore forces any transcript
 * seeded from it to differ.  The bus is a byte-boundary equality (host-checked
 * at the module seam, like the ingress codec round-trip); it is NOT yet an
 * in-parent_cs AIR constraint (that is a later edge).
 */
struct FiatShamirSeedOwnershipBusV1 {
    alg_hash::Digest parent_binding_digest{};
    uint256 owned_seed{};
    std::array<FiatShamirShaByteOriginV1, 32> byte_origins{};
    bool canonical_roundtrip{false};
    uint256 commitment{};
    bool valid{false};
    std::string note;
};

/** Build the parent-owned seed image + per-byte ownership taxonomy for h_cj. */
[[nodiscard]] FiatShamirSeedOwnershipBusV1
BuildFiatShamirSeedOwnershipBusV1(
    const alg_hash::Digest& parent_binding_digest);

/**
 * Number of the 32 seed bytes that DIFFER from the parent-owned image.
 * 0 == the supplied seed is genuinely owned by (equal to) the binding digest.
 */
[[nodiscard]] uint32_t FiatShamirSeedBusViolations(
    const FiatShamirSeedOwnershipBusV1& bus, const uint256& seed);

/**
 * Exact SHA256d execution inventory for the legacy one-slot receipt.
 *
 * Unlike FiatShamirWitness, this contains each full challenge preimage,
 * including every rejected OOD draw, and expands it to canonical SHA
 * compression boundaries.  Legacy V3 still has an unbounded OOD rejection
 * loop, so `fixed_schedule` remains false even for an accepted finite proof.
 * Bounded programs (`ood_candidates>=1` with `rejection_loop_bounded`) lay a
 * fixed K-candidate window per OOD challenge and set `fixed_schedule=true`
 * when the all-rejected failure is proven <= 2^-target_bits.  This plan is
 * an exact input to recursive SHA shards, not a claim that those shards have
 * already been consumed by the normalized parent — `recursively_consumed`
 * and `kVerifierFiatShamirAirExecutable` stay false until the SHA AIR and
 * parent join measure green.
 */
struct FiatShamirShaExecutionPlanV1 {
    uint32_t calls{0};
    uint32_t non_sha_challenge_calls{0};
    uint64_t compression_instances{0};
    std::vector<FiatShamirShaCallV1> call;
    std::vector<stage3_hash_air::ShaManifest> manifest;
    std::vector<
        stage3_hash_air::FixedProgramBoundaryInstance>
        boundaries;
    bool exact_domain_tags_and_order{false};
    bool every_digest_matches_claim{false};
    bool exact_sha256d_padding_and_chaining{false};
    bool non_sha_challenges_match_claims{false};
    bool fixed_schedule{false};
    bool proof_codec_byte_origins_complete{false};
    bool recursively_consumed{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] FiatShamirShaExecutionPlanV1
BuildFiatShamirShaExecutionPlanV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof);

/**
 * Inventory of predicates that still block flipping
 * `kVerifierFiatShamirAirExecutable`.  Fail-closed: `executable_ready` is
 * true only when every conjunct below is measured green.  Does NOT flip the
 * constexpr — callers must keep Ready/CompleteFP false until this reports
 * ready AND the SHA AIR / parent join are differentially tested.
 */
struct VerifierFiatShamirAirChipGapV1 {
    bool bounded_ood_program_legislated{false};
    bool bounded_ood_rejection_loop_bounded{false};
    bool sha_execution_plan_valid{false};
    bool sha_fixed_schedule{false};
    bool sha_codec_origins_complete{false};
    bool sha_recursively_consumed{false};
    bool non_sha_challenges_recursively_consumed{false};
    bool challenge_selection_air_constrained{false};
    bool air_backed_all_kinds_reconstructed{false};
    bool whole_verifier_sha_equations_in_air{false};
    bool authority_eligible{false};
    /** Conjunction; must stay false until every field above is true. */
    bool executable_ready{false};
    uint32_t open_predicates{0};
    std::string note;
};

/**
 * Assess the SHA-FS chip gap against a concrete (program, seed, proof).
 * Prefer a bounded program (`BuildBoundedFiatShamirProgram`) when measuring
 * the fixed-schedule conjunct; legacy V3 programs correctly leave
 * `sha_fixed_schedule` false.
 *
 * When `program.ood_candidates>0`, the child's z1/z2 must equal the bounded
 * K-window selection under the same absorb prefix (consensus-bounded sampler).
 * Use AlignAlgAirProofOodToBoundedShaScheduleV1 to patch a host proof for
 * light schedule canaries — never for production Ready.
 */
[[nodiscard]] VerifierFiatShamirAirChipGapV1
AssessVerifierFiatShamirAirChipGapV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof);

/**
 * fs_selection_air ChallengeTable join for SHA-FS challenge selection.
 *
 * Replays the bounded/canonical transcript, pins each accepted challenge's
 * SHA256d digest bytes to the scalar the verifier consumes (batch lambda /
 * z1 / z2 / w / fold / query index, plus airq_lambda), and measures
 * BuildChallengeTableAirV1 with a one-row consumed tamper. Does NOT flip
 * kVerifierFiatShamirAirExecutable — only reports whether selection AIR
 * constraints hold on this (program, seed, proof).
 */
struct FiatShamirChallengeSelectionAirJoinV1 {
    uint32_t draws{0};
    uint32_t table_rows{0};
    uint32_t table_constraints{0};
    uint32_t table_violations{1};
    uint32_t rows_bound_to_consumed{0};
    uint32_t query_rows{0};
    uint32_t query_rows_bound_to_consumed_index{0};
    bool digest_plan_ready{false};
    bool table_valid{false};
    bool tamper_rejects{false};
    /** Gap predicate: table green + all rows bound + tamper red. */
    bool constrained{false};
    std::string note;
};

[[nodiscard]] FiatShamirChallengeSelectionAirJoinV1
MeasureFiatShamirChallengeSelectionAirJoinV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof);

/**
 * AIR-backed reconstruction of all eight FS challenge kinds from the child's
 * SHA transcript digests (BuildFiatShamirAirBackedWitnessV1).
 *
 * Pins each kind's decoder input to the accepted SHA256d digest bytes, checks
 * covers_all_challenge_types, binds reconstructed values to the consumed
 * batch/airq challenges, and requires a one-input tamper to diverge. Does NOT
 * flip kVerifierFiatShamirAirExecutable.
 */
struct FiatShamirAirBackedAllKindsV1 {
    uint32_t kinds_reconstructed{0};
    uint32_t kinds_required{8};
    uint32_t values_bound_to_consumed{0};
    bool digest_plan_ready{false};
    bool covers_all_challenge_types{false};
    bool values_match_consumed{false};
    bool tamper_diverges{false};
    /** Gap predicate: 8/8 in-AIR + bound + tamper red. */
    bool reconstructed{false};
    std::string note;
};

[[nodiscard]] FiatShamirAirBackedAllKindsV1
MeasureFiatShamirAirBackedAllKindsV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof);

/**
 * Parent SHA-shard recursive consumption for the bounded Fiat–Shamir plan.
 *
 * Reuses MultiRow-V2 SHA scheduling: each exact SHA256d call is recorded,
 * sharded at ≤63 compressions, and joined by the arity-four recursive
 * manifest. Every call expands to exact SHA manifests/boundaries; the first
 * call additionally builds a FixedProgram vertical witness-boundary instance
 * whose AIR columns satisfy the constraint system (recursive consumer seam).
 * A recursive-node child-statement tamper and a boundary final-word tamper
 * must both go red. Does NOT flip kVerifierFiatShamirAirExecutable —
 * whole-verifier SHA equations remain a separate gap predicate.
 */
struct FiatShamirShaRecursivelyConsumedV1 {
    uint32_t sha_calls{0};
    uint64_t compression_instances{0};
    uint32_t parent_shards{0};
    uint32_t recursive_levels{0};
    uint32_t recursive_nodes{0};
    uint32_t shards_joined{0};
    uint32_t calls_boundary_air_green{0};
    bool digest_plan_ready{false};
    bool schedule_exact{false};
    bool shard_boundary_airs_execute{false};
    bool arity_four_join_complete{false};
    bool join_tamper_rejects{false};
    bool boundary_tamper_rejects{false};
    /** Gap predicate: schedule + join + boundary AIRs + both tampers. */
    bool consumed{false};
    std::string note;
};

[[nodiscard]] FiatShamirShaRecursivelyConsumedV1
MeasureFiatShamirShaRecursivelyConsumedV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof);

/**
 * Proof-owned recursive consumer for the non-SHA Fiat-Shamir challenges
 * (live Poseidon2 airq_lambda route). Fail-closed: requires the SHA plan's
 * non-SHA claim match, a query-sound P2 companion with zero violations, a
 * forced-limb tamper that goes red, and ProveConsumerEndpointFriP2V1 ok.
 * Does NOT flip kVerifierFiatShamirAirExecutable.
 */
struct FiatShamirNonShaChallengesRecursivelyConsumedV1 {
    uint32_t non_sha_calls{0};
    bool digest_plan_ready{false};
    bool non_sha_claims_match{false};
    bool p2_companion_valid{false};
    bool p2_query_sound{false};
    bool p2_tamper_rejects{false};
    bool consumer_fri_ok{false};
    bool consumed{false};
    std::string note;
};

[[nodiscard]] FiatShamirNonShaChallengesRecursivelyConsumedV1
MeasureFiatShamirNonShaChallengesRecursivelyConsumedV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof);

/**
 * Whole-verifier SHA equations: every Fiat-Shamir SHA256d call builds a
 * vertical boundary AIR that satisfies, and a final-word tamper diverges.
 * Stronger than the recursive-consume canary (which AIR-checks the first call
 * only). Does NOT flip kVerifierFiatShamirAirExecutable.
 */
struct FiatShamirWholeVerifierShaEquationsInAirV1 {
    uint32_t sha_calls{0};
    uint32_t calls_air_green{0};
    bool digest_plan_ready{false};
    bool every_call_boundary_air_satisfies{false};
    bool boundary_tamper_rejects{false};
    bool in_air{false};
    std::string note;
};

[[nodiscard]] FiatShamirWholeVerifierShaEquationsInAirV1
MeasureFiatShamirWholeVerifierShaEquationsInAirV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof);

/**
 * Rewrite batch.lambda/z1/z2/w/fold/query draws to the SHA256d transcript
 * selection for `program` (ood_candidates>=1 for the OOD window).  Leaves a
 * P2-squeezed production proof's FRI openings inconsistent with the new z —
 * light schedule / digest-match canaries only. Prefer
 * Fri3AlgShaFsBoundedOodCanaryBatchCommit for honest bounded SHA sampling.
 * Returns false if the program is not bounded or the window exhausts.
 */
[[nodiscard]] bool AlignAlgAirProofOodToBoundedShaScheduleV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    AlgAirProof& child_proof,
    std::string* why = nullptr);

[[nodiscard]] FiatShamirReplayResult ReplayFiatShamirWitness(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof,
    const FiatShamirWitness& witness);

/**
 * Canonical commitment to all child batch bytes and supplemental AIR
 * openings. This closes host-side omission/reorder/substitution ambiguity;
 * it is not a replacement for in-AIR proof equations.
 */
[[nodiscard]] uint256 ComputeVerifierChildProofCommitment(
    const AlgAirProof& child_proof);

struct VerifierProofRowBinding {
    uint32_t program_row{0};
    uint256 source_commitment{};

    bool operator==(const VerifierProofRowBinding&) const = default;
};

struct VerifierProofBinding {
    uint256 program_commitment{};
    std::vector<uint256> child_proof_commitments;
    std::vector<uint256> fiat_shamir_witness_commitments;
    std::vector<uint256> ctl_child_commitments;
    std::vector<VerifierProofRowBinding> rows;
    bool scheduler_capacity_sufficient{false};
    bool proof_equations_air_bound{false};
    bool valid{false};
    std::string note;

    bool operator==(const VerifierProofBinding&) const = default;
};

[[nodiscard]] VerifierProofBinding BuildVerifierProofBinding(
    const VerifierProgram& program,
    const uint256& child_fs_seed,
    const std::vector<AlgAirProof>& child_proofs,
    const std::vector<RCStage3CtlChildPin>& ctl_pins);
[[nodiscard]] bool ValidateVerifierProofBinding(
    const VerifierProgram& program,
    const uint256& child_fs_seed,
    const std::vector<AlgAirProof>& child_proofs,
    const std::vector<RCStage3CtlChildPin>& ctl_pins,
    const VerifierProofBinding& binding,
    std::string* why = nullptr);

/**
 * Executable host-side whole-verifier differential witness.  It combines:
 *   - the canonical normalized row schedule,
 *   - exact native Fiat-Shamir replay for every child,
 *   - complete native AirQuotientVerify for every child,
 *   - the proof-derived algebraic V_CS witness and violation scan, and
 *   - canonical CTL/proof/row commitments.
 *
 * `valid` means all host and currently implemented algebraic checks agree.  It
 * deliberately does not mean the SHA transcript or proof-row bindings are
 * constrained inside the recursive AIR; recursive_air_complete remains false
 * until those chips and equality constraints land.
 */
struct WholeVerifierWitness {
    VerifierProgram program;
    FiatShamirProgram fiat_shamir_program;
    std::vector<FiatShamirWitness> fiat_shamir_witnesses;
    std::vector<FiatShamirReplayResult> replay_results;
    VerifierProofBinding proof_binding;
    air_recurse::AggregateWitness algebraic_mirror;
    std::vector<bool> native_child_accepts;
    uint32_t algebraic_violations{0};
    uint64_t child_proof_bytes{0};
    uint64_t transcript_replay_micros{0};
    uint64_t native_verify_micros{0};
    uint64_t algebraic_witness_micros{0};
    uint64_t algebraic_scan_micros{0};
    bool all_transcripts_replayed{false};
    bool all_native_children_accepted{false};
    bool algebraic_mirror_satisfied{false};
    bool legacy_q192_v3_only{true};
    bool dual_q128_v5_target_supported{false};
    bool recursive_air_complete{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] WholeVerifierWitness BuildWholeVerifierWitness(
    const VerifierProgram& program,
    const air_quotient::AirConstraintSystem<Fp3>& child_cs,
    const uint256& child_fs_seed,
    const std::vector<AlgAirProof>& child_proofs,
    const std::vector<RCStage3CtlChildPin>& ctl_pins,
    const air_recurse::VerifierAirFamilies& families = {});

/**
 * Selected shared-master V5 host differential. This joins the exact finite
 * dual transcript witness to the authoritative native proof verifier. It is
 * intentionally separate from WholeVerifierWitness because the recursive
 * AirQuotientProof API still carries the legacy single-lane V3 batch.
 */
struct DualQ128HostVerifierWitness {
    Fri3AlgDualTranscriptWitness transcript;
    uint64_t proof_bytes{0};
    uint64_t transcript_replay_micros{0};
    uint64_t native_verify_micros{0};
    bool native_proof_accepted{false};
    bool recursive_proof_api_supports_v5{false};
    bool recursive_air_complete{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] DualQ128HostVerifierWitness
BuildDualQ128HostVerifierWitness(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed);

/**
 * Canonical verifier schedule for the three-group MultiRow-V2/Split-RAP
 * proof used by AirQuotientProveRowsSplitRap.
 *
 * Every proof field or host-verifier equality is represented exactly once.
 * Large group rows are time-multiplexed, so the verifier width is independent
 * of |R0|, |Rdep| and |Rq|.  The group widths remain parameters of the public
 * program and are not inferred from attacker-provided opening vectors.
 */
enum class MultiRowV2CheckKindV1 : uint8_t {
    ProofMetadata = 1,
    BaseColumnIndex = 2,
    GroupMetadata = 3,
    GroupRoot = 4,
    ColumnLength = 5,
    OodPoint = 6,
    EvaluationPairAbsorb = 7,
    IndependentPcsAlpha = 8,
    DeepWeight = 9,
    FoldRoot = 10,
    FoldChallenge = 11,
    QueryIndex = 12,
    CurrentGroupValue = 13,
    NextGroupValue = 14,
    CurrentMerkleStep = 15,
    NextMerkleStep = 16,
    FoldOpeningIndex = 17,
    FoldMerkleStep = 18,
    DeepIdentity = 19,
    FoldIdentity = 20,
    FinalFold = 21,
    TerminalRoot = 22,
    QuotientIdentity = 23,
    Padding = 24,
    CurrentMerkleSibling = 25,
    NextMerkleSibling = 26,
    FoldOpeningValue = 27,
    FoldMerkleSibling = 28,
    TerminalFinalValue = 29,
};

struct MultiRowV2ProgramRowV1 {
    MultiRowV2CheckKindV1 kind{
        MultiRowV2CheckKindV1::Padding};
    uint32_t query{0};
    uint32_t group{0};
    uint32_t layer{0};
    uint32_t item{0};
    uint32_t active_lanes{0};

    bool operator==(
        const MultiRowV2ProgramRowV1&) const = default;
};

struct MultiRowV2SplitRapProgramV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t quotient_len{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    uint32_t merkle_depth{0};
    uint32_t fold_count{0};
    uint32_t query_count{0};
    std::array<uint32_t, 3> group_widths{};
    std::vector<uint32_t> base_column_indices;
    uint32_t poseidon_permutation_rows{0};
    uint32_t active_rows{0};
    uint32_t air_rows{0};
    uint256 program_statement{};
    bool exact_three_group_partition{false};
    bool independent_pcs_alpha_schedule{false};
    bool current_next_schedule_complete{false};
    bool quotient_identity_scheduled{false};
    std::vector<MultiRowV2ProgramRowV1> rows;
};

[[nodiscard]] MultiRowV2SplitRapProgramV1
BuildCanonicalMultiRowV2SplitRapProgramV1(
    const air_quotient::AirConstraintSystem<Fp3>& child_cs,
    const std::vector<uint32_t>& base_column_indices);

[[nodiscard]] bool
ValidateCanonicalMultiRowV2SplitRapProgramV1(
    const air_quotient::AirConstraintSystem<Fp3>& child_cs,
    const MultiRowV2SplitRapProgramV1& program,
    std::string* why = nullptr);

struct MultiRowV2CheckWitnessV1 {
    MultiRowV2ProgramRowV1 program;
    std::array<Fp3, 4> claimed{};
    std::array<Fp3, 4> replayed{};

    bool operator==(
        const MultiRowV2CheckWitnessV1& other) const
    {
        if (!(program == other.program)) return false;
        for (uint32_t lane = 0; lane < claimed.size(); ++lane) {
            if (!gkr_field::Eq(
                    claimed[lane], other.claimed[lane]) ||
                !gkr_field::Eq(
                    replayed[lane], other.replayed[lane])) {
                return false;
            }
        }
        return true;
    }
};

enum MultiRowV2VerifierColumnV1 : uint32_t {
    kMultiRowV2Active = 0,
    kMultiRowV2Kind,
    kMultiRowV2Query,
    kMultiRowV2Group,
    kMultiRowV2Layer,
    kMultiRowV2Item,
    kMultiRowV2ActiveLanes,
    kMultiRowV2Expected0,
    kMultiRowV2Expected1,
    kMultiRowV2Expected2,
    kMultiRowV2Expected3,
    kMultiRowV2Claimed0,
    kMultiRowV2Claimed1,
    kMultiRowV2Claimed2,
    kMultiRowV2Claimed3,
    kMultiRowV2LocallyAccepted,
    kMultiRowV2VerifierColumns,
};

enum class MultiRowV2VerifierOutputKindV1 : uint8_t {
    GroupRoot = 1,
    AirConstraintLambda = 2,
    OodPoint = 3,
    IndependentPcsAlpha = 4,
    DeepWeight = 5,
    FoldChallenge = 6,
    QueryIndex = 7,
    FinalValue = 8,
};

struct MultiRowV2VerifierOutputV1 {
    MultiRowV2VerifierOutputKindV1 kind{
        MultiRowV2VerifierOutputKindV1::GroupRoot};
    uint32_t item{0};
    uint32_t coordinate{0};
    Fp3 value{};

    bool operator==(
        const MultiRowV2VerifierOutputV1& other) const
    {
        return kind == other.kind &&
            item == other.item &&
            coordinate == other.coordinate &&
            gkr_field::Eq(value, other.value);
    }
};

enum class MultiRowV2TranscriptShaCallKindV1 : uint8_t {
    AirConstraintLambda = 1,
    FriSeed = 2,
    OodCandidate = 3,
    IndependentPcsAlpha = 4,
    DeepWeight = 5,
    FoldChallenge = 6,
    QueryIndex = 7,
};

/**
 * One exact SHA256d invocation in protocol order.  `new_shared_prefix_blocks`
 * are full first-round transcript blocks first reached before this call.
 * They are executed once and reused by every call at the same prefix.
 * `first_round_tail_blocks` starts from that authenticated SHA state and
 * includes the residual transcript bytes, call suffix and SHA padding.
 */
struct MultiRowV2TranscriptShaCallV1 {
    uint32_t ordinal{0};
    MultiRowV2TranscriptShaCallKindV1 kind{
        MultiRowV2TranscriptShaCallKindV1::
            AirConstraintLambda};
    uint32_t item{0};
    uint32_t block{0};
    uint64_t transcript_bytes{0};
    uint32_t suffix_bytes{0};
    uint32_t new_shared_prefix_blocks{0};
    uint32_t shared_prefix_blocks{0};
    uint32_t first_round_tail_blocks{0};
    uint32_t second_round_blocks{1};
    uint64_t unique_compression_begin{0};
    uint32_t unique_compression_count{0};
    uint64_t naive_compression_count{0};
    /** Exact SHA256d preimage, including every domain/label/index byte. */
    std::vector<unsigned char> preimage;
    uint256 digest{};
    uint256 call_statement{};

    bool operator==(
        const MultiRowV2TranscriptShaCallV1&) const = default;
};

struct MultiRowV2TranscriptShaShardV1 {
    uint32_t shard{0};
    uint64_t compression_begin{0};
    uint32_t compression_count{0};
    uint32_t first_call{0};
    uint32_t last_call{0};
    uint256 shard_statement{};

    bool operator==(
        const MultiRowV2TranscriptShaShardV1&) const = default;
};

struct MultiRowV2TranscriptRecursiveNodeV1 {
    uint32_t level{0};
    uint32_t index{0};
    uint32_t child_count{0};
    std::array<uint256, 4> child_statements{};
    uint256 node_statement{};

    bool operator==(
        const MultiRowV2TranscriptRecursiveNodeV1&) const = default;
};

/**
 * Exact shared-prefix SHA execution and arity-four consumption manifest.
 *
 * The plan is executable scheduling data, not a recursive proof.  It remains
 * fail-closed until every shard has a fixed-program SHA AIR proof and each
 * arity-four node verifies its children inside the normalized parent.
 */
struct MultiRowV2TranscriptShaPlanV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint32_t max_compressions_per_shard{63};
    uint64_t naive_compressions{0};
    uint64_t unique_shared_prefix_compressions{0};
    uint64_t unique_call_tail_compressions{0};
    uint64_t unique_total_compressions{0};
    uint32_t sha256d_calls{0};
    uint32_t parent_shards{0};
    uint32_t recursive_levels{0};
    uint32_t proof_owned_shards{0};
    uint32_t recursively_consumed_shards{0};
    uint256 schedule_statement{};
    uint256 recursive_root_statement{};
    bool exact_call_order{false};
    bool every_compression_sharded_once{false};
    bool shard_capacity_respected{false};
    bool arity_four_manifest_complete{false};
    bool sha_shard_proofs_execute{false};
    bool normalized_recursive_consumption_complete{false};
    std::vector<MultiRowV2TranscriptShaCallV1> calls;
    std::vector<MultiRowV2TranscriptShaShardV1> shards;
    std::vector<MultiRowV2TranscriptRecursiveNodeV1>
        recursive_nodes;
};

struct MultiRowV2TranscriptShaCallExecutionV1 {
    uint32_t ordinal{0};
    uint32_t first_boundary{0};
    uint32_t compression_count{0};
    uint256 manifest_commitment{};
    uint256 digest{};

    bool operator==(
        const MultiRowV2TranscriptShaCallExecutionV1&) const =
        default;
};

/**
 * Exact SHA256d execution inventory for the canonical MultiRow-V2 transcript.
 *
 * Every call carries its full preimage and is expanded into canonical
 * fixed-program compression boundaries. This fixes domain tags, absorption
 * order, padding, chaining and digest byte order. Recursive consumption stays
 * false until private message bytes are proof-codec-owned and each SHA shard
 * is itself verified by the normalized parent.
 */
struct MultiRowV2TranscriptShaExecutionPlanV1 {
    uint16_t version{1};
    uint32_t calls{0};
    uint64_t compression_instances{0};
    uint32_t vertical_shards{0};
    uint32_t max_compressions_per_shard{63};
    std::vector<stage3_hash_air::ShaManifest>
        manifests;
    std::vector<
        stage3_hash_air::FixedProgramBoundaryInstance>
        boundaries;
    std::vector<
        MultiRowV2TranscriptShaCallExecutionV1>
        call_execution;
    bool exact_preimages{false};
    bool exact_sha256d_padding_and_chaining{false};
    bool every_digest_matches_call{false};
    bool canonical_compression_program{false};
    bool witness_owned_inputs_linked_to_proof_codec{false};
    bool challenge_selection_air_constrained{false};
    bool query_reduction_air_constrained{false};
    bool recursively_consumed{false};
    bool valid{false};
    std::string note;

    bool operator==(
        const MultiRowV2TranscriptShaExecutionPlanV1&) const =
        default;
};

[[nodiscard]] MultiRowV2TranscriptShaExecutionPlanV1
BuildMultiRowV2TranscriptShaExecutionPlanV1(
    const MultiRowV2TranscriptShaPlanV1& plan);

[[nodiscard]] bool
ValidateMultiRowV2TranscriptShaExecutionPlanV1(
    const MultiRowV2TranscriptShaPlanV1& schedule,
    const MultiRowV2TranscriptShaExecutionPlanV1& execution,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateMultiRowV2TranscriptShaPlanV1(
    const MultiRowV2TranscriptShaPlanV1& plan,
    std::string* why = nullptr);

struct MultiRowV2PoseidonPermutationAuditV1 {
    uint32_t permutation{0};
    alg_hash::State input{};
    alg_hash::State output{};
    uint256 permutation_statement{};

    bool operator==(
        const MultiRowV2PoseidonPermutationAuditV1&) const =
        default;
};

/**
 * Exact local permutation/layout audit.  All 12 state inputs and all 12
 * decomposed-AIR outputs are compared with the canonical operation log.
 * Semantic proof-cell producers and downstream consumers intentionally remain
 * a separate counter: layout equality must not be confused with proof-row
 * copy closure.
 */
struct MultiRowV2PoseidonAliasPlanV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint32_t permutation_count{0};
    uint32_t layout_input_alias_cells{0};
    uint32_t layout_output_alias_cells{0};
    uint32_t semantic_source_alias_cells{0};
    uint32_t semantic_consumer_alias_cells{0};
    uint32_t recursively_consumed_alias_cells{0};
    uint256 alias_statement{};
    bool exact_permutation_order{false};
    bool layout_aliases_complete{false};
    bool semantic_aliases_complete{false};
    std::vector<MultiRowV2PoseidonPermutationAuditV1>
        permutations;
};

/**
 * Exact local execution mirror of AirQuotientVerifyRowsSplitRap.
 *
 * The canonical preprocessed rows pin the proof version/metadata, ordered
 * roots, transcript challenges, every current/next opening, every Merkle
 * accumulator, DEEP/fold/final identities and the AIR quotient identity.
 * `host_verifier_accepted` is mandatory before this witness can be built.
 *
 * This is the reusable child-verifier relation consumed by an arity parent.
 * V1 still reports zero normalized-recursive ownership: the parent must prove
 * the AlgHash/SHA transcript and Merkle permutations rather than treating
 * these locally reconstructed preprocessed values as public constants.
 */
struct MultiRowV2SplitRapVerifierWitnessV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint256 public_fs_seed{};
    uint256 program_statement{};
    uint256 proof_statement{};
    uint256 output_statement{};
    uint32_t checked_rows{0};
    uint32_t exported_cells{0};
    uint32_t local_directly_checked_cells{0};
    uint32_t normalized_recursive_cells{0};
    bool canonical_program{false};
    bool host_verifier_accepted{false};
    bool transcript_replayed_exactly{false};
    bool all_independent_pcs_alphas_derived{false};
    bool all_current_next_openings_bound{false};
    bool all_merkle_paths_replayed{false};
    bool all_deep_fold_identities_checked{false};
    bool all_quotient_identities_checked{false};
    bool preprocessed_relation_satisfied{false};
    bool alg_hash_poseidon_permutations_constrained{false};
    bool alg_hash_io_aliases_to_proof_rows_complete{false};
    bool sha_transcript_air_constrained{false};
    bool parent_hash_chips_execute{false};
    bool normalized_recursive_consumption_complete{false};
    bool production_authority_ready{false};
    MultiRowV2TranscriptShaPlanV1 transcript_sha_plan;
    MultiRowV2TranscriptShaExecutionPlanV1
        transcript_sha_execution;
    MultiRowV2PoseidonAliasPlanV1 poseidon_alias_plan;
    std::vector<MultiRowV2CheckWitnessV1> checks;
    std::vector<MultiRowV2VerifierOutputV1> outputs;
    air_quotient::AirConstraintSystem<Fp3> constraint_system;
    std::vector<std::vector<Fp3>> witness_columns;
};

[[nodiscard]] MultiRowV2SplitRapVerifierWitnessV1
BuildMultiRowV2SplitRapVerifierWitnessV1(
    const air_quotient::AirConstraintSystem<Fp3>& child_cs,
    const MultiRowV2SplitRapProgramV1& program,
    const air_quotient::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed);

[[nodiscard]] bool VerifyMultiRowV2SplitRapVerifierWitnessV1(
    const air_quotient::AirConstraintSystem<Fp3>& child_cs,
    const MultiRowV2SplitRapProgramV1& program,
    const air_quotient::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed,
    const MultiRowV2SplitRapVerifierWitnessV1& witness,
    std::string* why = nullptr);

[[nodiscard]] std::vector<MultiRowV2VerifierOutputV1>
ExportMultiRowV2SplitRapVerifierOutputsV1(
    const MultiRowV2SplitRapVerifierWitnessV1& witness);

inline constexpr uint16_t kChunkRlcPcsVersionV1 = 1;
inline constexpr uint32_t kChunkRlcArityV1 = 4;
inline constexpr uint32_t kChunkRlcRecursiveColumnCapV1 =
    16384;

struct ChunkRlcOpeningV1 {
    uint32_t query{0};
    uint32_t current_index{0};
    uint32_t next_index{0};
    Fp3 current_value{};
    Fp3 next_value{};

    bool operator==(const ChunkRlcOpeningV1& other) const
    {
        return query == other.query &&
            current_index == other.current_index &&
            next_index == other.next_index &&
            gkr_field::Eq(
                current_value, other.current_value) &&
            gkr_field::Eq(
                next_value, other.next_value);
    }
};

struct ChunkRlcReceiptV1 {
    uint32_t chunk{0};
    uint32_t first_column{0};
    uint32_t column_count{0};
    alg_hash::Digest full_chunk_root{};
    alg_hash::Digest rlc_column_root{};
    uint256 precommit_statement{};
    uint256 coefficient_statement{};
    uint256 receipt_statement{};
    std::vector<Fp3> independent_coefficients;
    std::vector<ChunkRlcOpeningV1> openings;
    air_quotient::AirConstraintSystem<Fp3>
        local_relation;
    std::vector<std::vector<Fp3>>
        local_relation_columns;
    bool full_chunk_committed_before_coefficients{false};
    bool independent_coefficients_derived_post_commit{false};
    bool local_rlc_relation_satisfied{false};
    bool current_next_openings_complete{false};
};

struct ChunkRlcAggregateNodeV1 {
    uint32_t level{0};
    uint32_t index{0};
    uint32_t child_count{0};
    std::array<uint256, kChunkRlcArityV1>
        child_statements{};
    uint256 node_statement{};

    bool operator==(const ChunkRlcAggregateNodeV1&) const =
        default;
};

struct ChunkRlcPcsStatementV1 {
    uint16_t version{kChunkRlcPcsVersionV1};
    bool valid{false};
    std::string note;
    uint32_t trace_rows{0};
    uint32_t total_columns{0};
    uint32_t chunk_columns{0};
    uint32_t chunk_count{0};
    uint32_t next_step{0};
    uint32_t query_count{0};
    uint256 public_seed{};
    uint256 ordered_precommit_statement{};
    uint256 root_statement{};
    uint64_t locally_checked_cells{0};
    uint32_t recursively_consumed_receipts{0};
    bool exact_column_partition{false};
    bool commitments_precede_challenges{false};
    bool independent_post_commit_coefficients{false};
    bool one_current_next_rlc_per_chunk_query{false};
    bool arity_four_receipt_tree_complete{false};
    /**
     * Fail-closed V1 gap. The chunk RLC relation binds the committed columns
     * to their compressed codewords, but it does not yet prove the original
     * verifier constraint polynomial when one constraint reads columns from
     * two or more chunks, nor equality-link its quotient column.
     */
    bool original_constraint_relation_bound{false};
    bool cross_chunk_constraint_manifest_complete{false};
    bool original_quotient_linked{false};
    bool normalized_recursive_consumption_complete{false};
    bool production_authority_ready{false};
    std::vector<ChunkRlcReceiptV1> receipts;
    std::vector<ChunkRlcAggregateNodeV1>
        aggregate_nodes;
};

/**
 * Executable V1 chunk relation. The input columns are partitioned in their
 * canonical order. Every chunk's full row tree is committed before any
 * coefficient is derived. The local AIR then enforces, at every trace row,
 *
 *   rlc = sum_j alpha[global_column_j] * column_j.
 *
 * Only the RLC column's current/next values are exported to the receipt.
 */
[[nodiscard]] ChunkRlcPcsStatementV1
BuildChunkRlcPcsStatementV1(
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& query_indices,
    uint32_t next_step,
    uint32_t chunk_columns,
    const uint256& public_seed);

[[nodiscard]] bool VerifyChunkRlcPcsStatementV1(
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& query_indices,
    const ChunkRlcPcsStatementV1& statement,
    std::string* why = nullptr);

/** Exact quotient/FRI domain of a chunk-RLC leaf constraint system. */
struct ChunkRlcLeafDomainAuditV1 {
    uint32_t trace_rows{0};
    uint64_t max_composed_degree{0};
    uint32_t quotient_len{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    bool exact_quotient_degree_accounting{false};
    bool backend_lde_cap_met{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ChunkRlcLeafDomainAuditV1
AssessChunkRlcLeafDomainV1(
    const air_quotient::AirConstraintSystem<Fp3>& leaf_cs);

struct ChunkRlcCostPlanV1 {
    uint32_t chunk_columns{0};
    uint32_t total_columns{0};
    uint32_t trace_rows{0};
    uint32_t query_count{0};
    uint32_t merkle_depth{0};
    uint32_t chunk_count{0};
    uint32_t aggregation_nodes{0};
    uint32_t aggregation_levels{0};
    uint32_t maximum_leaf_relation_width{0};
    uint32_t normalized_root_width{0};
    uint64_t normalized_root_active_rows{0};
    uint32_t normalized_root_trace_rows{0};
    uint64_t local_relation_cells{0};
    uint64_t leaf_max_composed_degree{0};
    uint32_t leaf_quotient_len{0};
    uint32_t leaf_n_coeffs{0};
    uint32_t leaf_n_lde{0};
    uint64_t all_leaf_base_witness_bytes{0};
    uint64_t all_leaf_lde_column_bytes{0};
    uint64_t estimated_all_leaf_proof_bytes{0};
    uint64_t estimated_root_opening_bytes{0};
    uint64_t root_verifier_target_micros{900000};
    uint64_t measured_root_verifier_micros{0};
    bool leaf_domain_exact{false};
    bool cost_arithmetic_exact{false};
    bool backend_caps_met{false};
    bool original_constraint_relation_bound{false};
    bool cross_chunk_constraint_manifest_complete{false};
    bool original_quotient_linked{false};
    bool timing_measured{false};
    bool timing_target_met{false};
    bool selected{false};
    std::string note;
};

struct ChunkRlcCostSelectionV1 {
    bool valid{false};
    std::string note;
    std::array<ChunkRlcCostPlanV1, 2> candidates;
    uint32_t selected_chunk_columns{0};
};

[[nodiscard]] ChunkRlcCostSelectionV1
AssessChunkRlcCostSelectionV1(
    uint32_t total_columns,
    uint32_t trace_rows,
    uint32_t query_count,
    uint32_t merkle_depth);

enum class ChunkRlcInterleavedPoseidonKindV1 : uint8_t {
    RlcLeaf = 1,
    MerkleNode = 2,
};

/**
 * Two-row selector-gated operation. Row zero is active and the proof opening
 * or sibling occupies the Poseidon input columns themselves. There is no
 * parallel alias column. Row one is canonical padding.
 */
struct ChunkRlcInterleavedPoseidonWitnessV1 {
    bool valid{false};
    std::string note;
    ChunkRlcInterleavedPoseidonKindV1 kind{
        ChunkRlcInterleavedPoseidonKindV1::RlcLeaf};
    uint32_t trace_rows{2};
    uint32_t trace_columns{0};
    uint32_t value_input_base{0};
    uint32_t sibling_input_base{0};
    uint32_t selector_column{0};
    alg_hash::Digest output{};
    air_quotient::AirConstraintSystem<Fp3>
        constraint_system;
    std::vector<std::vector<Fp3>> columns;
    bool proof_value_is_literal_permutation_input{false};
    bool sibling_is_literal_permutation_input{false};
};

[[nodiscard]] ChunkRlcInterleavedPoseidonWitnessV1
BuildChunkRlcInterleavedLeafV1(
    const Fp3& rlc_value, uint32_t index);

[[nodiscard]] ChunkRlcInterleavedPoseidonWitnessV1
BuildChunkRlcInterleavedNodeV1(
    const alg_hash::Digest& accumulator,
    const alg_hash::Digest& sibling,
    bool sibling_on_left);

/**
 * Inventory of predicates for flipping
 * `kMultiRowV2SplitRapVerifierAirLocalExecutable`.
 *
 * LocalExecutable means the exact MultiRow-V2 Split-RAP verifier AIR mirror
 * of `AirQuotientVerifyRowsSplitRap` executes: canonical three-group program,
 * host accept, local witness AIR green, openings/Merkle/DEEP/quotient checks,
 * Poseidon layout aliases, and the exact SHA schedule. RecursiveAuthority is
 * separate and stays false while semantic Poseidon I/O aliases, SHA transcript
 * AIR, and parent hash chips remain open.
 *
 * Fail-closed: `local_executable_ready` is true only when every local
 * conjunct is measured green AND the constexpr is true. Does not flip
 * RecursiveAuthority / CompleteFP / consensus authority.
 */
struct MultiRowV2SplitRapLocalExecutableGapV1 {
    bool canonical_program{false};
    bool host_verifier_accepted{false};
    bool local_witness_valid{false};
    bool local_witness_verified{false};
    bool openings_and_identities_checked{false};
    bool poseidon_layout_constrained{false};
    bool sha_schedule_exact{false};
    bool claimed_tamper_rejects{false};
    bool recursive_authority_still_open{false};
    /** Conjunction; true only after the LocalExecutable constexpr flips. */
    bool local_executable_ready{false};
    uint32_t open_predicates{0};
    std::string note;
};

[[nodiscard]] MultiRowV2SplitRapLocalExecutableGapV1
AssessMultiRowV2SplitRapLocalExecutableGapV1(
    const air_quotient::AirConstraintSystem<Fp3>& child_cs,
    const MultiRowV2SplitRapProgramV1& program,
    const air_quotient::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed);

inline constexpr bool kVerifierFixedSchedulerExecutable = true;
inline constexpr bool kVerifierScalarAirExecutable = true;
inline constexpr bool kWholeVerifierLegacyV3HostDifferentialExecutable = true;
inline constexpr bool kWholeVerifierDualQ128V5HostDifferentialExecutable =
    false;
inline constexpr bool kDualQ128V5HostTranscriptExecutable = true;
inline constexpr bool kWholeVerifierHostDifferentialExecutable =
    kWholeVerifierLegacyV3HostDifferentialExecutable;
inline constexpr bool kVerifierFiatShamirAirExecutable = false;
inline constexpr bool kVerifierProofRowsBoundInAir = false;
inline constexpr bool kWholeVerifierWitnessExecutable = false;
/**
 * Exact local MultiRow-V2 Split-RAP verifier AIR mirror is executable.
 * Evidence: AssessMultiRowV2SplitRapLocalExecutableGapV1 + CoupledBankEquality
 * child-verifier / recursive-consumption audits. RecursiveAuthority stays
 * false (semantic Poseidon I/O + SHA AIR + parent hash chips open).
 */
inline constexpr bool kMultiRowV2SplitRapVerifierAirLocalExecutable = true;
inline constexpr bool
    kMultiRowV2SplitRapVerifierAirRecursiveAuthority = false;
inline constexpr bool kVerifierAirConsensusAuthority = false;
inline constexpr bool kChunkRlcPcsV1ProductionAuthority = false;

static_assert(!kVerifierFiatShamirAirExecutable);
static_assert(!kVerifierProofRowsBoundInAir);
static_assert(!kWholeVerifierWitnessExecutable);
static_assert(kMultiRowV2SplitRapVerifierAirLocalExecutable);
static_assert(!kMultiRowV2SplitRapVerifierAirRecursiveAuthority);
static_assert(!kVerifierAirConsensusAuthority);
static_assert(!kChunkRlcPcsV1ProductionAuthority);

} // namespace matmul::v4::rc::stage3_verifier_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_VERIFIER_AIR_H
