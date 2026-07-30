// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V6_FS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V6_FS_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// Experimental Stage-3 V6 Fiat-Shamir transcript.
//
// V5 uses SHA256d for every transcript draw.  That is native-compatible but
// forces a bit-level SHA verifier into V_CS.  V6 is an explicitly different
// proof format: SHA256d is retained only for the block/public-statement
// boundary, represented here as 32 public bytes, while every recursive
// master/child binding and challenge frame is a domain-separated AlgHash
// sponge invocation.
//
// One trace row is one fully-decomposed Poseidon2 permutation.  The AIR:
//   * proves all 118 x^7 S-boxes with quadratic identities;
//   * proves the rate/capacity sponge transition between blocks;
//   * proves the previous-frame digest is absorbed by the next frame;
//   * pins all framing, public-statement, and padding words; and
//   * equality-constrains proof-derived payload slots to eight explicit
//     external-source columns.
//
// The external-source columns are an integration seam, not a trust oracle.
// They become proof-derived only when the recursive child verifier writes its
// row roots/evaluations into those same columns (or CTL-equality-constrains
// them).  Standalone V6 proofs therefore remain R&D and cannot enable
// authority.  This module intentionally exposes that final condition.

namespace matmul::v4::rc::stage3_v6_fs {

using gkr_field::Fp;
using gkr_field::Fp3;

inline constexpr uint16_t kVersion = 6;
inline constexpr Fp kTranscriptDomain =
    UINT64_C(0x3653465f43525842); // LE "BXRC_FS6", canonical in Goldilocks.
inline constexpr uint32_t kRate = alg_hash::kAlgHashRate;
inline constexpr uint32_t kDigest = alg_hash::kAlgHashDigestLen;
inline constexpr uint32_t kMaxFrames = 4096;
inline constexpr uint32_t kMaxPayloadWords = 1U << 20;
inline constexpr uint32_t kQueryCandidatesPerIndex = 4;
inline constexpr uint32_t kMaxQueryDomainBits = 32;
inline constexpr uint64_t kConditionalGlobalSiteCount = 66480699;

enum class FrameKind : uint16_t {
    MasterStatement = 1,
    LaneSeed = 2,
    BatchCoefficient = 3,
    OodCandidate = 4,
    DeepWeight = 5,
    FoldChallenge = 6,
    QueryCandidate = 7,
    AirQuotientChallenge = 8,
    AbsorbCommitment = 9,
    AbsorbEvaluation = 10,
};

enum class WordOrigin : uint8_t {
    /** Protocol literal (domain/version/frame headers and padding). */
    Fixed = 1,
    /** Reconstructed from the block/public statement by the verifier. */
    PublicStatement = 2,
    /** Must equal a cell exported by the recursive child-verifier AIR. */
    ProofDerived = 3,
};

struct Word {
    Fp value{0};
    WordOrigin origin{WordOrigin::ProofDerived};
    bool operator==(const Word&) const = default;
};

struct Frame {
    FrameKind kind{FrameKind::AbsorbCommitment};
    uint16_t lane{0};
    uint32_t index{0};
    std::vector<Word> payload;
    bool operator==(const Frame&) const = default;
};

struct PayloadCell {
    uint32_t frame{0};
    uint32_t payload_index{0};
    uint32_t trace_row{0};
    uint32_t rate_lane{0};
    WordOrigin origin{WordOrigin::ProofDerived};
    bool operator==(const PayloadCell&) const = default;
};

struct ProgramRow {
    uint32_t frame{0};
    uint32_t block{0};
    bool active{false};
    bool start{false};
    bool end{false};
    bool continue_from_previous_row{false};
    bool chain_digest_to_next_frame{false};
    bool query_candidate_end{false};
    bool query_group_start{false};
    bool query_group_final{false};
    /** End row of one of the four bounded dual-OOD candidate frames. */
    bool ood_candidate_end{false};
    /** Start/final rows of either two-candidate OOD selection group. */
    bool ood_group_start{false};
    bool ood_group_final{false};
    /** True for candidates 2/3, which select z2 distinct from z1. */
    bool ood_second_point{false};
    bool ood_z1_group_start{false};
    bool ood_z2_group_start{false};
    bool ood_z1_candidate_end{false};
    bool ood_z2_candidate_end{false};
    uint8_t query_domain_bits{0};
    std::array<Fp, kRate> source{};
    std::array<uint8_t, kRate> fixed_mask{};
    std::array<uint8_t, kRate> proof_mask{};
};

struct Program {
    std::vector<Frame> frames;
    std::vector<ProgramRow> rows;
    std::vector<PayloadCell> payload_cells;
    uint32_t active_rows{0};
    uint32_t trace_rows{0};
    /** Zero for programs without queries; otherwise one canonical domain. */
    uint8_t query_domain_bits{0};
    bool valid{false};
    std::string note;
};

/** Compile exact event framing plus 10* field padding. */
[[nodiscard]] Program BuildProgram(const std::vector<Frame>& frames);

/**
 * Extend a canonical program with inactive all-zero rows to an explicitly
 * selected power-of-two trace domain.  Padding changes neither the frame
 * encoding nor any transcript digest; it is only the deterministic
 * same-trace alignment used when the normalized child verifier already has a
 * larger row domain.
 */
[[nodiscard]] Program PadProgramToTraceRows(const Program& program,
                                            uint32_t trace_rows);
[[nodiscard]] bool ValidateProgram(const Program& program,
                                   std::string* why = nullptr);

struct Layout {
    stage3_poseidon_air::Layout poseidon;
    uint32_t source_base{0};
    uint32_t external_source_base{0};
    uint32_t active{0};
    uint32_t start{0};
    uint32_t continue_from_previous_row{0};
    uint32_t chain_digest_to_next_frame{0};
    uint32_t fixed_mask_base{0};
    uint32_t fixed_value_base{0};
    uint32_t proof_mask_base{0};
    uint32_t query_bit_base{0};
    uint32_t query_top_ones_prefix_base{0};
    uint32_t query_low_zero_prefix_base{0};
    uint32_t query_valid{0};
    uint32_t query_selected{0};
    uint32_t query_have_selected{0};
    uint32_t query_index_term{0};
    uint32_t query_index_accumulator{0};
    uint32_t query_reduced_index{0};
    uint32_t query_candidate_end{0};
    uint32_t query_group_start{0};
    uint32_t query_group_final{0};
    uint32_t ood_c1_inverse{0};
    uint32_t ood_c2_inverse{0};
    uint32_t ood_c1_nonzero{0};
    uint32_t ood_c2_nonzero{0};
    uint32_t ood_ext_nonzero{0};
    uint32_t ood_diff_inverse_base{0};
    uint32_t ood_diff_nonzero_base{0};
    uint32_t ood_diff_any01{0};
    uint32_t ood_distinct{0};
    uint32_t ood_valid{0};
    uint32_t ood_selected{0};
    uint32_t ood_have_selected{0};
    uint32_t ood_accepted_z1_base{0};
    uint32_t ood_accepted_z2_base{0};
    uint32_t ood_candidate_end{0};
    uint32_t ood_group_start{0};
    uint32_t ood_group_final{0};
    uint32_t ood_second_point{0};
    uint32_t ood_z1_group_start{0};
    uint32_t ood_z2_group_start{0};
    uint32_t ood_z1_candidate_end{0};
    uint32_t ood_z2_candidate_end{0};

    [[nodiscard]] uint32_t Source(uint32_t lane) const
    {
        return source_base + lane;
    }
    [[nodiscard]] uint32_t ExternalSource(uint32_t lane) const
    {
        return external_source_base + lane;
    }
    [[nodiscard]] uint32_t FixedMask(uint32_t lane) const
    {
        return fixed_mask_base + lane;
    }
    [[nodiscard]] uint32_t FixedValue(uint32_t lane) const
    {
        return fixed_value_base + lane;
    }
    [[nodiscard]] uint32_t ProofMask(uint32_t lane) const
    {
        return proof_mask_base + lane;
    }
    [[nodiscard]] uint32_t QueryBit(uint32_t bit) const
    {
        return query_bit_base + bit;
    }
    [[nodiscard]] uint32_t QueryTopOnesPrefix(uint32_t step) const
    {
        return query_top_ones_prefix_base + step;
    }
    [[nodiscard]] uint32_t QueryLowZeroPrefix(uint32_t step) const
    {
        return query_low_zero_prefix_base + step;
    }
    [[nodiscard]] uint32_t OodDiffInverse(uint32_t coordinate) const
    {
        return ood_diff_inverse_base + coordinate;
    }
    [[nodiscard]] uint32_t OodDiffNonzero(uint32_t coordinate) const
    {
        return ood_diff_nonzero_base + coordinate;
    }
    [[nodiscard]] uint32_t OodAcceptedZ1(uint32_t coordinate) const
    {
        return ood_accepted_z1_base + coordinate;
    }
    [[nodiscard]] uint32_t OodAcceptedZ2(uint32_t coordinate) const
    {
        return ood_accepted_z2_base + coordinate;
    }
    [[nodiscard]] uint32_t End() const
    {
        return ood_z2_candidate_end + 1;
    }
};

[[nodiscard]] Layout CanonicalLayout(uint32_t base = 0);

/**
 * Build the transcript AIR.  Fixed/public values and row scheduling are
 * canonical preprocessed columns.  Proof-derived payloads are constrained to
 * external_source[0..8), which the combined recursive verifier must populate.
 */
[[nodiscard]] bool BuildConstraintSystem(
    const Program& program,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why = nullptr);

struct Witness {
    std::vector<std::vector<Fp3>> columns;
    std::vector<alg_hash::Digest> frame_digests;
    /** True only as a statement about this chip's equality constraints. */
    bool proof_payload_equality_hooks_satisfied{false};
    /** False until the combined child verifier owns external-source columns. */
    bool external_sources_owned_by_child_verifier{false};
    bool valid{false};
    std::string note;
};

struct QueryReductionResult {
    uint16_t lane{0};
    uint32_t query{0};
    uint32_t selected_candidate{0};
    uint32_t reduced_index{0};
    bool valid{false};

    bool operator==(const QueryReductionResult&) const = default;
};

struct OodSelectionResult {
    uint16_t lane{0};
    Fp3 z1{};
    Fp3 z2{};
    uint32_t z1_candidate{0};
    uint32_t z2_candidate{0};
    uint32_t z1_trace_row{0};
    uint32_t z2_trace_row{0};
    bool valid{false};
};

[[nodiscard]] Witness BuildWitness(const Program& program);

/** Extract the AIR-witnessed first-valid reductions from final query rows. */
[[nodiscard]] std::vector<QueryReductionResult>
ExtractQueryReductions(const Program& program, const Witness& witness);

/** Extract the AIR-witnessed first-valid z1/z2 selections for each lane. */
[[nodiscard]] std::vector<OodSelectionResult>
ExtractOodSelections(const Program& program, const Witness& witness);

/**
 * Exact threshold facts for Goldilocks p=2^64-2^32+1 and a power-of-two
 * domain N<=2^32:
 *
 *   p mod N = 1, limit=floor(p/N)N=p-1.
 *
 * Hence the only canonical rejected field value is p-1. Four fixed
 * candidates fail with probability p^-4 in the ideal-output model.
 */
struct QuerySamplerAssessment {
    uint32_t domain_size{0};
    uint32_t domain_bits{0};
    uint32_t candidates{0};
    uint64_t rejection_threshold{0};
    long double exhaustion_bits_per_index{0};
    long double exhaustion_bits_after_sites{0};
    bool exact_power_of_two_reduction{false};
    bool air_executable{false};
    bool global_transcript_independence_proved{false};
};

[[nodiscard]] QuerySamplerAssessment
AssessQuerySampler(uint32_t domain_size,
                   uint64_t global_sites = kConditionalGlobalSiteCount);

/**
 * Same-trace direct-alias composer for the normalized child verifier.
 *
 * The child system occupies columns [0, child_cs.n_columns). Its eight
 * contiguous export-bus columns are used directly as Layout::ExternalSource;
 * no transcript-owned mirror columns exist in the composed layout. The child
 * constraints and transcript constraints are proved by one quotient.
 *
 * This is stronger and narrower than a LogUp/CTL copy: it has deterministic
 * equality and no additional challenge/error term, but requires the child
 * scheduler to publish all transcript payloads on the aligned eight-lane bus.
 * The generic composer is executable. The normalized V5 verifier publishes
 * all 48 proof-derived root/evaluation/fold payload cells. This closes source
 * ownership only; V5 still consumes SHA-derived challenges, so challenge
 * feedback and recursive production authority remain false.
 */
struct DirectAliasComposition {
    Layout transcript;
    uint32_t child_columns{0};
    uint32_t child_export_base{0};
    uint32_t total_columns{0};
    bool same_trace{false};
    bool direct_alias{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildDirectAliasConstraintSystem(
    const Program& program,
    const air_quotient::AirConstraintSystem<Fp3>& child_cs,
    uint32_t child_export_base,
    air_quotient::AirConstraintSystem<Fp3>& out,
    DirectAliasComposition* composition = nullptr,
    std::string* why = nullptr);

[[nodiscard]] Witness BuildDirectAliasWitness(
    const Program& program,
    const air_quotient::AirConstraintSystem<Fp3>& child_cs,
    const std::vector<std::vector<Fp3>>& child_columns,
    uint32_t child_export_base);

[[nodiscard]] uint32_t CountViolations(
    const air_quotient::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t* first_row = nullptr,
    std::string* first_constraint = nullptr);

struct MasterBindingInput {
    std::array<uint8_t, 32> public_statement_sha256d{};
    uint32_t batch_columns{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    std::array<alg_hash::Digest, 2> ordered_lane_row_roots{};
};

/**
 * Minimal V6 master schedule:
 *   master(public SHA boundary, shape, ordered proof-derived row roots)
 *   -> lane-0 seed -> lane-1 seed.
 *
 * The row-root words use WordOrigin::ProofDerived and therefore exercise the
 * external equality seam.  Lane order is fixed in the payload and frame tags.
 */
[[nodiscard]] Program BuildMasterBindingProgram(
    const MasterBindingInput& input);

struct LaneProofInput {
    /** Commitment to the pre-quotient trace columns. */
    alg_hash::Digest trace_root{};
    /** The selected V6 row-wise trace+quotient commitment. */
    alg_hash::Digest row_root{};
    /** Six Fp words per committed Fp3 column, z1 then z2. */
    std::vector<Fp3> evals_z1;
    std::vector<Fp3> evals_z2;
    std::vector<alg_hash::Digest> fold_roots;
};

struct FullTranscriptInput {
    MasterBindingInput master;
    uint32_t folds{0};
    uint32_t queries{128};
    std::array<LaneProofInput, 2> lane;
};

/**
 * Canonical finite V6 transcript for both ordered lanes:
 *
 * trace-root absorb -> AIR quotient draw -> lane seed -> W independent batch
 * draws -> four OOD candidates (two for z1, two for z2) -> AIR-selected
 * accepted z1/z2 -> evaluation absorb -> two DEEP weights ->
 * (fold-root absorb, fold draw)* -> query-candidate draws.
 *
 * All commitments/evaluations are ProofDerived words.  Challenge frames have
 * no prover payload: their digest is forced by the preceding chained state.
 * Each query uses four QueryCandidate frames with one fixed public domain
 * word. The integrated sampler proves canonical bits, accepts the first
 * digest below p-1, and reduces its low log2(n_lde) bits. Exhaustion rejects.
 */
[[nodiscard]] Program BuildFullTranscriptProgram(
    const FullTranscriptInput& input);

enum class Scenario : uint8_t {
    ExistingSha256dAir = 1,
    AlgebraicV6 = 2,
    HostDigestHybrid = 3,
};

struct ScenarioAssessment {
    Scenario scenario{};
    bool existing_wire_compatible{false};
    bool algebraic_transcript_in_air{false};
    bool master_and_lane_binding_in_air{false};
    bool proof_payload_equality_seam{false};
    bool host_digest_trust_removed{false};
    bool query_reduction_closed{false};
    bool child_source_integration_closed{false};
    bool production_authority_ready{false};
    uint32_t trace_width{0};
    uint64_t permutation_or_compression_rows{0};
    std::string verdict;
};

/** Exact comparison for a caller-supplied V6 program. */
[[nodiscard]] std::array<ScenarioAssessment, 3>
AssessScenarios(const Program& v6_program,
                uint64_t sha256d_compression_blocks);

inline constexpr bool kV6AlgebraicTranscriptAirExecutable = true;
inline constexpr bool kV6MasterLaneBindingAirExecutable = true;
inline constexpr bool kV6QueryReductionAirExecutable = true;
inline constexpr bool kV6OodSelectionAirExecutable = true;
inline constexpr bool kV6DirectAliasComposerExecutable = true;
/** Every proof-derived full-transcript payload now has a named normalized-V5
 * witness source and selected same-trace equality in stage3_v5_v6_bus. This
 * does not imply challenge feedback or recursive authority. */
inline constexpr bool kV6ChildProofSourceIntegrationExecutable = true;
inline constexpr bool kV6RecursiveAuthorityReady = false;
static_assert(kV6ChildProofSourceIntegrationExecutable);
static_assert(kV6OodSelectionAirExecutable);
static_assert(!kV6RecursiveAuthorityReady);

} // namespace matmul::v4::rc::stage3_v6_fs

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V6_FS_H
