// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V5_V6_BUS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V5_V6_BUS_H

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_v6_fs.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v5_v6_bus {

namespace aq = air_quotient;
namespace ar = air_recurse;
namespace v6 = stage3_v6_fs;
using gkr_field::Fp3;

enum class TranscriptScope : uint8_t {
    /** Ordered V5 row roots into the V6 master/lane binding. */
    MasterBinding = 1,
    /** Roots, evaluations, folds and query schedule for both V5 lanes. */
    FullTranscript = 2,
};

struct PayloadMapping {
    v6::PayloadCell payload;
    ar::VerifierAirTranscriptOutput source;
    uint32_t export_column{0};
    uint32_t selector_column{0};
    bool source_is_v5_witness_column{false};
    bool equation_consumer_present{false};
    bool same_trace_constrained{false};
};

/**
 * A constraint-native, time-multiplexed V5 -> V6 bus.
 *
 * normalized_v5 is repeated on a larger power-of-two trace domain when the
 * V6 transcript needs more rows.  This is sound for the current normalized
 * V_CS because every assembled V_CS constraint is row-local/everywhere.
 * Eight time-multiplexed export witness columns and one immutable selector
 * per proof-derived payload cell are appended. Each selector activates
 * exactly once and degree-two aliases that export cell directly to its named
 * normalized-V5 root terminal or evaluation-claim column. V6 ExternalSource
 * aliases the witness columns directly, so one quotient proves both sides.
 */
struct SameTraceComposition {
    bool valid{false};
    std::string note;
    TranscriptScope scope{TranscriptScope::MasterBinding};

    v6::Program program;
    aq::AirConstraintSystem<Fp3> normalized_v5;
    std::vector<std::vector<Fp3>> normalized_v5_columns;
    aq::AirConstraintSystem<Fp3> combined;
    std::vector<std::vector<Fp3>> combined_columns;
    std::vector<ar::ChildPublicInputs> lane_pis;
    v6::Layout transcript_layout;

    uint32_t original_v5_rows{0};
    uint32_t aligned_rows{0};
    uint32_t original_v5_columns{0};
    uint32_t export_base{0};
    uint32_t selector_base{0};
    uint32_t combined_columns_count{0};
    uint32_t combined_constraints{0};
    uint32_t proof_derived_payload_cells{0};
    uint32_t row_root_payload_cells_directly_aliased{0};
    uint32_t transcript_payload_cells_directly_aliased{0};
    uint32_t selector_columns{0};
    std::vector<PayloadMapping> payload_mappings;

    uint64_t witness_build_micros{0};
    uint64_t constraint_scan_micros{0};

    bool native_v5_verified{false};
    bool finite_v5_transcript_replayed_on_host{false};
    bool export_bus_constrained_in_air{false};
    bool literal_v6_alias{false};
    /** V6 challenges still do not replace the SHA-derived V5 constants. */
    bool v6_challenges_drive_v5_equations{false};
    bool sha_public_boundary_in_air{false};
    bool production_authority_ready{false};
};

enum class ChallengeFeedbackFamily : uint8_t {
    AirQuotient = 1,
    BatchCoefficient = 2,
    OodPoint = 3,
    DeepWeight = 4,
    FoldChallenge = 5,
    QueryIndex = 6,
};

/** Audit record for one base-field cell consumed by a normalized V5 equation. */
struct ChallengeFeedbackCell {
    ChallengeFeedbackFamily family{
        ChallengeFeedbackFamily::AirQuotient};
    uint32_t lane{0};
    uint32_t item_index{0};
    uint32_t coordinate{0};
    const char* v5_equation_consumer{nullptr};
    bool v5_equation_source_materialized{false};
    bool v6_source_present{false};
    bool v6_source_is_virtual_permutation_output{false};
    uint32_t v6_trace_row{0};
    uint32_t v6_source_column{0};
    uint32_t v6_output_lane{0};
    bool honest_values_equal{false};
    bool direct_same_trace_alias{false};
};

struct ChallengeFeedbackAssessment {
    bool valid{false};
    std::string note;
    std::vector<ChallengeFeedbackCell> cells;
    uint32_t required_cells{0};
    uint32_t structurally_addressable_v6_cells{0};
    uint32_t honest_value_equal_cells{0};
    uint32_t direct_same_trace_alias_cells{0};
    bool v5_uses_sha256d_transcript{true};
    bool v6_uses_algebraic_transcript{true};
    bool derivation_domains_equal{false};
    bool ood_selection_output_in_v6{false};
    bool feedback_complete{false};
};

/**
 * Exact fail-closed inventory of all V5 FS cells consumed by quotient, DEEP,
 * fold and query equations. It names structurally corresponding V6 output
 * cells but never counts coincidental value equality as a semantic alias.
 */
[[nodiscard]] ChallengeFeedbackAssessment
AssessChallengeFeedback(const SameTraceComposition& composition);

inline constexpr uint32_t kV5SemanticConsumerCells = 304;
inline constexpr uint32_t kV5SemanticConsumerRows = 512;
inline constexpr uint32_t kV5SemanticConsumerColumns = 8;
inline constexpr uint32_t kStage3RecursiveColumnCap = 16384;

/**
 * Canonical local obligation joining one AIR-checked V6 challenge output to
 * the exact SHA-derived value consumed by the already-verified V5 child.
 *
 * `values_equal` is an observed fact, never an ownership claim.  In the
 * current V5/V6 pair most rows are expected to differ because the transcripts
 * intentionally use different hash domains.
 */
struct NormalizedChallengeFeedbackCellV1 {
    uint32_t ordinal{0};
    ChallengeFeedbackFamily family{
        ChallengeFeedbackFamily::AirQuotient};
    uint32_t lane{0};
    uint32_t item_index{0};
    uint32_t coordinate{0};
    uint8_t consumer{0};
    uint32_t v6_trace_row{0};
    uint32_t v6_source_column{0};
    uint32_t v6_output_lane{0};
    gkr_field::Fp v6_output_value{0};
    gkr_field::Fp v5_public_input{0};
    bool values_equal{false};

    bool operator==(
        const NormalizedChallengeFeedbackCellV1&) const = default;
};

enum NormalizedChallengeFeedbackColumnV1 : uint32_t {
    kNormalizedFeedbackActive = 0,
    kNormalizedFeedbackFamily,
    kNormalizedFeedbackLane,
    kNormalizedFeedbackItem,
    kNormalizedFeedbackCoordinate,
    kNormalizedFeedbackConsumer,
    kNormalizedFeedbackV6Row,
    kNormalizedFeedbackV6Column,
    kNormalizedFeedbackExpectedV6,
    kNormalizedFeedbackExpectedV5,
    kNormalizedFeedbackWitnessV6,
    kNormalizedFeedbackWitnessV5,
    kNormalizedFeedbackColumns,
};

/**
 * Migration canary for direct V6 -> V5 feedback.
 *
 * The verifier reconstructs both sides from one checked SameTraceComposition:
 * V6 output cells come from its locally AIR-satisfied algebraic transcript
 * witness and V5 inputs come from the natively verified/replayed child public
 * inputs.  Twelve vertically multiplexed columns then pin both values and
 * impose `active * (v6 - v5) = 0` on all 304 canonical rows.
 *
 * This receipt deliberately separates three facts:
 *  - canonical local source/input binding can be complete;
 *  - the current V5-SHA and V6-AlgHash values can still differ; and
 *  - neither local fact means a recursive parent cryptographically consumed
 *    the child proofs.
 *
 * Consequently `valid` means the fail-closed obligation was reconstructed
 * canonically. `current_assignment_satisfies_local_equality` is the separate
 * direct-feedback result and remains false for the current proof formats.
 */
struct NormalizedChallengeFeedbackReceiptV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint256 schedule_commitment{};
    uint256 v6_output_commitment{};
    uint256 v5_input_commitment{};
    uint256 receipt_commitment{};
    uint32_t required_cells{0};
    uint32_t structurally_mapped_cells{0};
    uint32_t locally_equal_cells{0};
    uint32_t local_equality_obligations{0};
    uint32_t local_equality_violations{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    bool canonical_order{false};
    bool v6_outputs_checked_locally{false};
    bool v5_public_inputs_checked_locally{false};
    bool local_binding_complete{false};
    bool current_assignment_satisfies_local_equality{false};
    bool recursively_child_proof_owned{false};
    std::vector<NormalizedChallengeFeedbackCellV1> cells;
    aq::AirConstraintSystem<Fp3> constraint_system;
    std::vector<std::vector<Fp3>> witness_columns;
};

[[nodiscard]] NormalizedChallengeFeedbackReceiptV1
BuildNormalizedChallengeFeedbackReceiptV1(
    const SameTraceComposition& composition);

/**
 * Validate the canonical binding transcript, including exact omission,
 * ordering and value checks.  This does not require the two transcript
 * domains to produce equal values.
 */
[[nodiscard]] bool ValidateNormalizedChallengeFeedbackReceiptV1(
    const SameTraceComposition& composition,
    const NormalizedChallengeFeedbackReceiptV1& receipt,
    std::string* why = nullptr);

/**
 * Stronger migration gate: canonical binding plus all 304 local equalities.
 * It fails closed for the current SHA-V5 / AlgHash-V6 pair.
 */
[[nodiscard]] bool VerifyNormalizedChallengeFeedbackLocalEqualityV1(
    const SameTraceComposition& composition,
    const NormalizedChallengeFeedbackReceiptV1& receipt,
    std::string* why = nullptr);

enum class V5EquationConsumer : uint8_t {
    PerPointIdentity = 1,
    DeepIdentity = 2,
    DeepDenominatorAndEvaluation = 3,
    FoldRelation = 4,
    QueryPreprocessedSchedule = 5,
};

enum V5SemanticConsumerColumn : uint32_t {
    kV5SemanticActive = 0,
    kV5SemanticExpected,
    kV5SemanticFamily,
    kV5SemanticLane,
    kV5SemanticItem,
    kV5SemanticCoordinate,
    kV5SemanticConsumer,
    /** The sole proof-owned, time-multiplexed V5 consumer-value column. */
    kV5SemanticWitness,
};
static_assert(
    kV5SemanticWitness + 1 == kV5SemanticConsumerColumns);

/** Exact semantic coordinate of one SHA-derived base-field value consumed by
 * a normalized V5 verifier equation. The V6 source fields are informational:
 * they preserve the structural correspondence but are never an equality
 * alias or challenge-feedback claim. */
struct V5SemanticConsumerCell {
    uint32_t semantic_row{0};
    ChallengeFeedbackFamily family{
        ChallengeFeedbackFamily::AirQuotient};
    uint32_t lane{0};
    uint32_t item_index{0};
    uint32_t coordinate{0};
    V5EquationConsumer consumer{
        V5EquationConsumer::PerPointIdentity};
    uint32_t algebraic_v6_trace_row{0};
    uint32_t algebraic_v6_source_column{0};
    uint32_t algebraic_v6_output_lane{0};
    gkr_field::Fp expected_v5_value{0};
    bool direct_v6_challenge_feedback{false};
};

struct V5SemanticMaterialization {
    bool valid{false};
    std::string note;
    uint256 public_boundary_commitment{};
    uint256 air_seed{};
    uint32_t logical_cells{0};
    uint32_t trace_rows{0};
    uint32_t total_columns{0};
    uint32_t proof_owned_columns{0};
    uint32_t verifier_fixed_columns{0};
    uint32_t width_overhead{0};
    uint64_t trace_cell_overhead{0};
    bool under_recursive_column_cap{false};
    bool verifier_recomputed_sha_boundary{false};
    bool all_cells_semantically_mapped{false};
    bool all_cells_air_equality_constrained{false};
    bool direct_v6_challenge_feedback{false};
    std::vector<V5SemanticConsumerCell> cells;
    aq::AirConstraintSystem<Fp3> constraint_system;
    std::vector<std::vector<Fp3>> witness_columns;
};

/**
 * One cell of the cycle-free V5-SHA -> V6 committed-feedback bridge.
 *
 * This is deliberately not an AlgHash challenge claim.  The value is the
 * exact SHA-derived public input consumed by the named V5 equation.  It is
 * placed in a proof-owned export column, equality-constrained to that V5
 * consumer value, and absorbed as a proof-derived word by a domain-separated
 * V6 frame on the same trace row.
 */
struct V5CommittedFeedbackCell {
    uint32_t semantic_row{0};
    ChallengeFeedbackFamily family{
        ChallengeFeedbackFamily::AirQuotient};
    uint32_t lane{0};
    uint32_t item_index{0};
    uint32_t coordinate{0};
    V5EquationConsumer consumer{
        V5EquationConsumer::PerPointIdentity};
    v6::PayloadCell payload;
    uint32_t export_column{0};
    uint32_t expected_column{0};
    uint32_t mask_column{0};
    bool v5_consumer_equality{false};
    bool v6_proof_payload_equality{false};
    bool same_trace_alias{false};
    /** Always false until the SHA/rejection-sampling chip owns the source. */
    bool algebraic_v6_challenge_derivation{false};
    /** True only when a same-parent SHA/conversion producer owns this cell. */
    bool recursive_sha_derivation{false};
};

/**
 * Executable split-transcript bridge.
 *
 * The bridge removes the combinational V6-output -> V5-verifier cycle:
 * SHA-derived V5 challenge cells are fixed before the normalized verifier is
 * executed, then a separate V6 sponge commits their ordered typed stream.
 * Eight time-multiplexed export columns are shared literally with
 * Layout::ExternalSource.  Eight verifier-fixed expected columns pin the
 * exact V5 consumer values and eight verifier-fixed masks pin the schedule.
 *
 * This closes direct committed equality for 304/304 cells.  It does not prove
 * SHA256d, uniform-candidate selection, or query reduction inside recursion,
 * and therefore does not make the algebraic V6 challenges drive V5.
 */
struct V5CommittedFeedbackComposition {
    bool valid{false};
    std::string note;
    uint256 public_boundary_commitment{};
    v6::Program program;
    v6::Layout transcript_layout;
    aq::AirConstraintSystem<Fp3> combined;
    std::vector<std::vector<Fp3>> combined_columns;
    std::vector<V5CommittedFeedbackCell> cells;
    uint32_t trace_rows{0};
    uint32_t export_base{0};
    uint32_t expected_base{0};
    uint32_t mask_base{0};
    uint32_t bridge_columns{0};
    uint32_t combined_columns_count{0};
    uint32_t combined_constraints{0};
    uint64_t combined_trace_cells{0};
    uint32_t committed_same_trace_feedback_alias_cells{0};
    uint32_t algebraic_v6_challenge_derivation_cells{0};
    uint32_t recursive_sha_derivation_cells{0};
    bool under_recursive_column_cap{false};
    bool ordered_feedback_stream_bound{false};
    bool sha_rejection_sampling_in_air{false};
    bool production_authority_ready{false};
};

[[nodiscard]] V5CommittedFeedbackComposition
BuildV5CommittedFeedbackComposition(
    const SameTraceComposition& composition);

[[nodiscard]] bool VerifyV5CommittedFeedbackComposition(
    const SameTraceComposition& composition,
    const uint256& public_boundary_commitment,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why = nullptr);

/**
 * Same-trace SHA producer for the AIR-quotient challenge family.
 *
 * One four-lane packed fixed-program SHA provenance table proves the complete
 * SHA256d compression chain for AirChallengeDigest.  Six digest words are
 * bit-decomposed and byte-order converted to the three Fp3 coordinates, then
 * selected equality constraints drive both lanes' six AirQuotient consumer
 * cells on the committed-feedback bus.  The fourth SHA lane is a canonical
 * duplicate padding lane because the packed chip has immutable arity four.
 *
 * The other 298 cells remain committed aliases only.  In particular this
 * construction does not claim the V5 uniform-Fp3 rejection sampler or query
 * index sampler have been arithmetized.
 */
struct V5ShaProducedFeedbackComposition {
    bool valid{false};
    std::string note;
    uint256 public_boundary_commitment{};
    uint256 combined_air_seed{};
    v6::Program program;
    v6::Layout transcript_layout;
    aq::AirConstraintSystem<Fp3> combined;
    std::vector<std::vector<Fp3>> combined_columns;
    std::vector<V5CommittedFeedbackCell> cells;
    uint32_t sha256d_compression_blocks{0};
    uint32_t packed_sha_lanes{0};
    uint32_t trace_rows{0};
    uint32_t sha_prefix_columns{0};
    uint32_t export_base{0};
    uint32_t digest_word_base{0};
    uint32_t digest_bit_base{0};
    uint32_t challenge_output_base{0};
    uint32_t derived_mask_base{0};
    uint32_t combined_columns_count{0};
    uint32_t combined_constraints{0};
    uint64_t combined_trace_cells{0};
    uint32_t committed_same_trace_feedback_alias_cells{0};
    uint32_t sha_air_derivation_cells{0};
    uint32_t recursive_sha_derivation_cells{0};
    uint32_t algebraic_v6_challenge_derivation_cells{0};
    bool sha_compression_provenance_in_same_air{false};
    bool digest_to_fp3_in_same_air{false};
    bool under_recursive_column_cap{false};
    bool production_authority_ready{false};
};

[[nodiscard]] V5ShaProducedFeedbackComposition
BuildV5ShaProducedFeedbackComposition(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed);

[[nodiscard]] bool VerifyV5ShaProducedFeedbackComposition(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed,
    const uint256& public_boundary_commitment,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why = nullptr);

/**
 * Split-RAP/MultiRow-V2 form of the six-cell AIR-lambda producer.
 *
 * R0 contains every challenge-independent packed-SHA base column and every
 * feedback/V6 column. Rdep contains exactly the two LogUp inverse columns
 * and running column in each of the four packed SHA lanes. This is the child
 * proof shape the normalized fixed-point verifier can recursively consume;
 * producing/verifying it locally does not itself increment recursive
 * ownership.
 */
struct V5AirLambdaSplitRapProofV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint256 semantic_boundary_commitment{};
    uint256 combined_air_seed{};
    uint256 proof_statement{};
    uint32_t trace_columns{0};
    uint32_t r0_columns{0};
    uint32_t rdep_columns{0};
    uint32_t locally_proved_cells{0};
    uint32_t normalized_recursive_cells{0};
    std::vector<uint32_t> base_column_indices;
    aq::AirQuotientSplitRapRowsProof quotient;
};

[[nodiscard]] V5AirLambdaSplitRapProofV1
ProveV5AirLambdaSplitRapV1(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed);

[[nodiscard]] bool VerifyV5AirLambdaSplitRapV1(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed,
    const V5AirLambdaSplitRapProofV1& proof,
    std::string* why = nullptr);

inline constexpr uint32_t
    kV5AirLambdaArityParentSlotsV1 = 4;
inline constexpr uint32_t
    kV5AirLambdaArityParentGroupsV1 = 3;
inline constexpr uint32_t
    kV5AirLambdaArityParentNextGroupsV1 = 2;
inline constexpr uint32_t
    kV5AirLambdaArityParentOutputsV1 = 6;

static_assert(kV5AirLambdaArityParentSlotsV1 == 4);
static_assert(kV5AirLambdaArityParentGroupsV1 == 3);
static_assert(kV5AirLambdaArityParentNextGroupsV1 == 2);
static_assert(kV5AirLambdaArityParentOutputsV1 == 6);

/**
 * Public adapter contract for one Split-RAP AirQ child in an arity-four
 * normalized parent.  This deliberately records zero recursively consumed
 * cells until the reusable in-AIR Split-RAP verifier executes these exact
 * openings and outputs.
 */
struct V5AirLambdaArityParentContractV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint32_t child_count{0};
    std::array<
        uint32_t, kV5AirLambdaArityParentGroupsV1>
        group_width{};
    std::array<
        uint32_t, kV5AirLambdaArityParentGroupsV1>
        current_group_openings{};
    std::array<
        uint32_t, kV5AirLambdaArityParentNextGroupsV1>
        next_group_openings{};
    std::array<
        Fp3, kV5AirLambdaArityParentOutputsV1>
        outputs{};
    std::array<
        uint256, kV5AirLambdaArityParentSlotsV1>
        child_commitment{};
    uint256 public_statement{};
    uint256 verifier_seed{};
    uint256 contract_commitment{};
    uint32_t normalized_recursive_cells{0};
    bool codec_canonical{false};
    bool canonical_padding{false};
    bool verifier_api_pending{true};
};

[[nodiscard]] V5AirLambdaArityParentContractV1
BuildV5AirLambdaArityParentContractV1(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed,
    const V5AirLambdaSplitRapProofV1& proof);

[[nodiscard]] bool
ValidateV5AirLambdaArityParentContractV1(
    const SameTraceComposition& composition,
    const uint256& child_fs_seed,
    const V5AirLambdaSplitRapProofV1& proof,
    const V5AirLambdaArityParentContractV1& contract,
    std::string* why = nullptr);

/**
 * Exact next-tier inventory derived from the authoritative V5 proof.
 *
 * This reconstructs every lane-seed, uniform-Fp3 and query-index SHA256d
 * preimage in protocol order, validates every sampled output against the
 * accepted proof, and expands each call into its exact SHA compression-block
 * count.  It is a fail-closed implementation plan, not a recursive proof:
 * counters remain pending when the required packed SHA instances do not fit
 * beside the feedback bus in one bounded-width parent.
 */
struct V5ShaProducerPlan {
    bool valid{false};
    std::string note;
    uint32_t lane_seed_sha256d_calls{0};
    uint32_t uniform_fp3_draws{0};
    uint32_t uniform_fp3_sha256d_calls{0};
    uint32_t uniform_sha_compression_blocks{0};
    uint32_t uniform_consumer_cells{0};
    uint32_t query_index_sha256d_calls{0};
    uint32_t query_sha_compression_blocks{0};
    uint32_t query_consumer_cells{0};
    uint32_t packed_provenance_instance_capacity{0};
    uint32_t uniform_minimum_parent_shards{0};
    uint32_t query_minimum_parent_shards{0};
    uint32_t currently_recursive_sha_cells{0};
    /** Cells backed by completed child SHA proofs but not yet consumed. */
    uint32_t proof_owned_sha_derivation_cells{0};
    /** Cells whose child SHA proofs execute inside a normalized parent. */
    uint32_t recursively_consumed_sha_derivation_cells{0};
    uint32_t pending_uniform_cells{0};
    uint32_t pending_query_cells{0};
    /** Greedy dependency-preserving shard loads; no draw/selector is split. */
    std::vector<uint32_t> uniform_shard_compression_blocks;
    std::vector<uint32_t> uniform_shard_consumer_cells;
    bool uniform_shards_preserve_typed_draws{false};
    bool uniform_output_root_equality_pending{true};
    std::vector<uint32_t> query_shard_compression_blocks;
    std::vector<uint32_t> query_shard_consumer_cells;
    /** Exact protocol-order calls: 2 lane seeds + 36 uniform digest calls. */
    std::vector<uint32_t>
        uniform_sha256d_compression_blocks_per_call;
    /** Exact protocol-order calls: lane 0's 128, then lane 1's 128. */
    std::vector<uint32_t>
        query_sha256d_compression_blocks_per_call;
    bool query_shards_preserve_typed_draws{false};
    bool query_output_root_equality_pending{true};
    bool all_preimages_replayed{false};
    bool all_uniform_outputs_match{false};
    bool all_query_outputs_match{false};
    bool uniform_fits_one_parent{false};
    bool query_fits_one_parent{false};
};

enum class V5TranscriptShaCallKind : uint8_t {
    AirQuotient = 1,
    LaneSeed = 2,
    UniformDigest = 3,
    QueryIndex = 4,
};

struct V5TranscriptShaCall {
    uint32_t ordinal{0};
    V5TranscriptShaCallKind kind{
        V5TranscriptShaCallKind::AirQuotient};
    uint32_t lane{0};
    uint32_t item{0};
    uint32_t hash_block{0};
    uint32_t compression_blocks{0};
    uint32_t parent_shard{0};
    uint32_t leaf_in_parent{0};
    uint32_t dependency_lane_seed_call{UINT32_MAX};
};

struct V5TranscriptConsumerSource {
    uint32_t semantic_row{0};
    ChallengeFeedbackFamily family{
        ChallengeFeedbackFamily::AirQuotient};
    uint32_t lane{0};
    uint32_t item_index{0};
    uint32_t coordinate{0};
    V5EquationConsumer consumer{
        V5EquationConsumer::PerPointIdentity};
    uint32_t parent_shard{0};
    uint32_t source_call_count{0};
    std::array<uint32_t, 8> source_call_ordinals{};
    uint32_t dependency_lane_seed_call{UINT32_MAX};
};

struct V5TranscriptFanoutLink {
    uint64_t link_id{0};
    uint32_t source_call_ordinal{0};
    uint32_t source_word{0};
    uint32_t target_count{0};
    std::vector<uint32_t> target_call_ordinals;
};

struct V5TranscriptShardProofContainer {
    uint16_t version{1};
    uint32_t parent_shard{0};
    uint256 public_schedule_statement{};
    std::vector<Fp3> claimed_outputs;
    std::vector<aq::AirQuotientRowsProof> leaf_proofs;
    aq::AirQuotientRowsProof aggregate_proof;
    bool aggregate_present{false};
    uint32_t proof_owned_cells{0};
    uint32_t recursively_consumed_cells{0};
};

struct V5TranscriptWitnessShard {
    uint32_t parent_shard{0};
    uint32_t compression_blocks{0};
    uint32_t consumer_cells{0};
    uint32_t leaf_count{0};
    std::vector<uint32_t> call_ordinals;
    std::vector<uint32_t> consumer_semantic_rows;
    uint256 public_schedule_statement{};
    V5TranscriptShardProofContainer proof;
};

struct V5FullTranscriptWitnessShardPlan {
    bool valid{false};
    std::string note;
    uint256 public_plan_statement{};
    uint32_t sha256d_calls{0};
    uint32_t prequery_sha256d_calls{0};
    uint32_t query_sha256d_calls{0};
    uint32_t parent_shards{0};
    uint32_t vertical_leaf_proofs{0};
    uint32_t mapped_consumer_cells{0};
    uint32_t proof_owned_sha_derivation_cells{0};
    uint32_t recursively_consumed_sha_derivation_cells{0};
    bool exact_304_source_mapping{false};
    bool fanout_safe_unique_link_ids{false};
    bool public_only_schedule_reconstruction{false};
    bool public_only_proof_verifier_reconstruction{false};
    std::vector<V5TranscriptShaCall> calls;
    std::vector<V5TranscriptConsumerSource> consumers;
    std::vector<V5TranscriptFanoutLink> fanout_links;
    std::vector<V5TranscriptWitnessShard> shards;
};

[[nodiscard]] V5FullTranscriptWitnessShardPlan
BuildV5FullTranscriptWitnessShardPlan(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed);

[[nodiscard]] bool ValidateV5FullTranscriptWitnessShardPlan(
    const V5FullTranscriptWitnessShardPlan& plan,
    std::string* why = nullptr);

/**
 * Per-family accounting for the canonical V5 SHA256d transcript adapter.
 *
 * `direct_sha256d_calls` counts unique SHA calls whose outputs directly
 * determine cells in this family. The two lane-seed calls are dependency
 * calls and are accounted once at the adapter level, rather than being
 * double-counted through their 146-way fan-out.
 */
struct V5TranscriptFamilyCoverageV1 {
    ChallengeFeedbackFamily family{
        ChallengeFeedbackFamily::AirQuotient};
    uint32_t semantic_cells{0};
    uint32_t direct_sha256d_calls{0};
    uint32_t direct_sha256d_compression_blocks{0};
    uint32_t locally_executable_cells{0};
    uint32_t proof_owned_cells{0};
    uint32_t recursively_consumed_cells{0};
    uint32_t pending_cells{0};

    bool operator==(
        const V5TranscriptFamilyCoverageV1&) const = default;
};

inline constexpr uint32_t kV5TranscriptUnificationRowsV1 = 512;

enum V5TranscriptUnificationColumnV1 : uint32_t {
    kV5TranscriptUnificationActive = 0,
    kV5TranscriptUnificationFamily,
    kV5TranscriptUnificationLane,
    kV5TranscriptUnificationItem,
    kV5TranscriptUnificationCoordinate,
    kV5TranscriptUnificationConsumer,
    kV5TranscriptUnificationSourceCallCount,
    kV5TranscriptUnificationParentShard,
    kV5TranscriptUnificationLocallyExecutable,
    kV5TranscriptUnificationProofOwned,
    kV5TranscriptUnificationRecursivelyConsumed,
    kV5TranscriptUnificationPending,
    kV5TranscriptUnificationColumns,
};

/**
 * Executable coverage canary for replacing incompatible V6 AlgHash feedback
 * with the exact V5 SHA256d/XOF transcript schedule.
 *
 * This adapter does not prove SHA execution. It commits to and reconstructs
 * the complete public 296-call/304-cell schedule, with proof ownership kept
 * separate from local executability. In V1 the six AirQuotient cells have a
 * local SHA producer, but none of the 304 cells is attached to a recursive
 * proof container, so all 304 remain pending.
 */
struct V5TranscriptUnificationCanaryV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint256 source_plan_statement{};
    uint256 public_schedule_statement{};
    uint32_t sha256d_calls{0};
    uint32_t direct_sha256d_calls{0};
    uint32_t dependency_sha256d_calls{0};
    uint32_t sha256d_compression_blocks{0};
    uint32_t direct_sha256d_compression_blocks{0};
    uint32_t dependency_sha256d_compression_blocks{0};
    uint32_t semantic_cells{0};
    uint32_t locally_executable_cells{0};
    uint32_t proof_owned_cells{0};
    uint32_t recursively_consumed_cells{0};
    uint32_t pending_cells{0};
    uint32_t direct_v6_to_v5_feedback_cells{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    bool exact_sha256d_call_inventory{false};
    bool exact_semantic_cell_inventory{false};
    bool v5_sha256d_xof_schedule_selected{false};
    bool incompatible_v6_alghash_feedback_rejected{false};
    bool public_schedule_cs_reconstructible{false};
    bool public_schedule_cs_satisfied{false};
    bool full_sha256d_execution_proved{false};
    bool complete_xof_selection_proved{false};
    bool public_proof_verifier_reconstructible{false};
    bool recursive_consumption_complete{false};
    bool production_authority_ready{false};
    std::array<V5TranscriptFamilyCoverageV1, 6> families{};
    aq::AirConstraintSystem<Fp3> public_constraint_system;
    std::vector<std::vector<Fp3>> public_columns;
};

[[nodiscard]] V5TranscriptUnificationCanaryV1
BuildV5TranscriptUnificationCanaryV1(
    const V5FullTranscriptWitnessShardPlan& plan);

/**
 * Reconstruct the coverage-only CS from the validated public plan. The
 * expected statement is mandatory and mismatches fail closed.
 */
[[nodiscard]] bool
ReconstructV5TranscriptUnificationPublicConstraintSystemV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const uint256& expected_public_schedule_statement,
    aq::AirConstraintSystem<Fp3>& constraint_system,
    std::vector<std::vector<Fp3>>& public_columns,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateV5TranscriptUnificationCanaryV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptUnificationCanaryV1& canary,
    std::string* why = nullptr);

struct V5FirstUniformVerticalShard {
    bool valid{false};
    std::string note;
    uint32_t compression_blocks{0};
    uint32_t consumer_cells{0};
    uint256 ordered_output_commitment{};
    uint256 vertical_air_seed{};
    uint32_t sampler_final_output_base{0};
    std::vector<Fp3> ordered_outputs;
    std::vector<stage3_hash_air::FixedProgramBoundaryInstance>
        boundaries;
    stage3_hash_air::FixedProgramVerticalProvenanceInstance
        sha_execution;
    uint32_t proof_owned_sha_derivation_cells{0};
    uint32_t recursively_consumed_sha_derivation_cells{0};
    bool sampler_selection_conversion_pending{true};
    bool output_root_equality_pending{true};
};

[[nodiscard]] V5FirstUniformVerticalShard
BuildV5FirstUniformVerticalShard(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed);

/**
 * Smallest executable witness-owned V5 transcript prefix.
 *
 * The prefix contains lane 0's SHA256d lane seed and the two SHA256d calls
 * used by its first uniform-Fp3 draw. Exact word links cover every SHA
 * chaining boundary; bit links cover the unaligned lane-seed digest embedded
 * in both draw preimages. A one-hot accepted-count state selects the first
 * three words below the Goldilocks modulus and equality-binds those three
 * outputs to the corresponding normalized-V5 batch-coefficient cells.
 *
 * This remains a local AIR execution until a proof/opening API exposes the
 * three exports to a normalized recursive parent.
 */
enum class V5UniformDrawRelationV1 : uint8_t {
    BatchCoefficient = 1,
    OodCandidate = 2,
    DeepWeight = 3,
    FoldChallenge = 4,
    QueryIndex = 5,
};

struct V5FirstUniformDrawWitnessPrefix {
    bool valid{false};
    std::string note;
    V5UniformDrawRelationV1 relation{
        V5UniformDrawRelationV1::BatchCoefficient};
    uint32_t lane{0};
    uint32_t batch_item{0};
    uint32_t compression_blocks{0};
    uint32_t exact_word_links{0};
    uint32_t digest_message_words{0};
    uint32_t message_bit_base{0};
    uint32_t candidate_bit_base{0};
    uint32_t draw_output_base{0};
    uint32_t accepted_count_base{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t v5_semantic_cell_count{0};
    uint256 prefix_statement{};
    /** Public seed of the witness-owned SHA/sampler AIR instance. */
    uint256 vertical_air_seed{};
    std::array<Fp3, 3> draw_output{};
    std::array<uint32_t, 3> v5_semantic_rows{};
    std::vector<stage3_hash_air::FixedProgramBoundaryInstance>
        boundaries;
    std::vector<std::vector<uint8_t>> public_external_masks;
    std::vector<stage3_hash_air::FixedProgramWitnessBoundaryLink>
        links;
    stage3_hash_air::FixedProgramVerticalWitnessBoundaryInstance
        sha_execution;
    uint32_t proof_owned_sha_derivation_cells{0};
    uint32_t recursively_consumed_sha_derivation_cells{0};
};

/** Reusable witness/CS builder for one `(lane, batch coefficient)` draw. */
[[nodiscard]] V5FirstUniformDrawWitnessPrefix
BuildV5BatchCoefficientDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t batch_item);

/** One SHA/uniform candidate used by the complete OOD selector. */
[[nodiscard]] V5FirstUniformDrawWitnessPrefix
BuildV5OodCandidateDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t candidate);

[[nodiscard]] V5FirstUniformDrawWitnessPrefix
BuildV5DeepWeightDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t item);

[[nodiscard]] V5FirstUniformDrawWitnessPrefix
BuildV5FoldChallengeDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t fold);

[[nodiscard]] V5FirstUniformDrawWitnessPrefix
BuildV5QueryIndexDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t query);

[[nodiscard]] V5FirstUniformDrawWitnessPrefix
BuildV5FirstUniformDrawWitnessPrefix(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed);

/**
 * Exact column/oracle partition for the sound two-epoch replacement.
 *
 * Transcript order is consensus-significant:
 *   1. absorb R0 (challenge-independent SHA base/metadata columns);
 *   2. derive SHA LogUp challenges and construct Rdep;
 *   3. absorb Rdep and derive the AIR constraint-batching challenge;
 *   4. construct/absorb Rq;
 *   5. derive one independent column RLC, dual OOD points, DEEP weights,
 *      folds and query indices over the ordered R0/Rdep/Rq roots.
 *
 * Every logical trace column appears in exactly one of R0/Rdep, and the
 * virtual quotient column appears only in Rq. The executable MultiRow-V2
 * backend opens every group at every shared current query site and separately
 * authenticates the next R0/Rdep rows needed by transition constraints.
 * `backend_executable` says only that this exact bounded proof/verifier path is
 * available; it does not imply global soundness accounting, recursive
 * consumption, durable consensus attachment, or authority readiness.
 */
enum class V5SplitFriGroupRole : uint8_t {
    R0Base = 1,
    Rdep = 2,
    Rq = 3,
};

struct V5SplitFriGroupPlan {
    V5SplitFriGroupRole role{
        V5SplitFriGroupRole::R0Base};
    uint32_t first_flattened_column{0};
    std::vector<uint32_t> air_column_indices;
    uint256 row_commitment{};
};

struct V5FirstUniformSplitFriPlan {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint256 prefix_statement{};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    uint32_t query_count{0};
    uint32_t quotient_virtual_column{0};
    uint256 group_schedule_commitment{};
    std::vector<V5SplitFriGroupPlan> groups;
    bool r0_precedes_sha_challenges{false};
    bool rdep_precedes_constraint_batch_challenge{false};
    bool rq_precedes_fri_challenges{false};
    bool ordered_roots_absorbed_once{false};
    bool one_rlc_deep_fold_over_all_groups{false};
    bool shared_query_opens_all_groups{false};
    bool logical_columns_partitioned_once{false};
    bool backend_executable{false};
    bool global_soundness_accounted{false};
    uint32_t proof_owned_sha_derivation_cells{0};
    uint32_t recursively_consumed_sha_derivation_cells{0};
};

[[nodiscard]] V5FirstUniformSplitFriPlan
BuildV5FirstUniformSplitFriPlan(
    const V5FirstUniformDrawWitnessPrefix& prefix);

[[nodiscard]] bool ValidateV5FirstUniformSplitFriPlan(
    const V5FirstUniformDrawWitnessPrefix& prefix,
    const V5FirstUniformSplitFriPlan& plan,
    std::string* why = nullptr);

/**
 * First concrete Split-RAP proof product. It proves the complete 13-block
 * SHA256d / uniform-rejection / first-three selection prefix and its three
 * equalities to normalized-V5 consumer cells. The three outputs are
 * proof-owned but not yet recursively consumed. This is not the full
 * 304-cell transcript and carries no authority-ready flag.
 */
struct V5FirstUniformSplitRapProof {
    uint16_t version{1};
    uint256 prefix_statement{};
    uint256 sha_public_statement{};
    uint256 vertical_air_seed{};
    uint256 canonical_r0{};
    std::array<Fp3, 3> proved_v5_exports{};
    aq::AirQuotientSplitRapRowsProof quotient;
    uint32_t proof_owned_v5_cells{0};
    uint32_t recursively_consumed_v5_cells{0};
    bool full_304_transcript{false};
};

struct V5FirstUniformSplitRapProveResult {
    bool ok{false};
    std::string note;
    V5FirstUniformSplitRapProof proof;
};

[[nodiscard]] V5FirstUniformSplitRapProveResult
ProveV5FirstUniformSplitRap(
    const V5FirstUniformDrawWitnessPrefix& prefix);

/**
 * Public-input verifier. The canonical prefix is regenerated from the
 * already-public child proof and composition. This verifies only the
 * first-uniform transcript relation; it does not replace verification of
 * `child` or authenticate a caller-constructed `composition`. The caller must
 * first verify/build those through the checked V5 child path.
 *
 * Before Split-RAP verification, the SHA CS is independently reconstructed
 * with all private external/final words redacted and only
 * program/masks/links/seed/R0 retained. Version 1 still rebuilds the bounded
 * canonical prefix to instantiate the sampler extension; a descriptor-only
 * builder is the verifier-time optimization seam.
 */
[[nodiscard]] bool VerifyV5FirstUniformSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV5BatchCoefficientDrawSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t batch_item,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV5OodCandidateDrawSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t candidate,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV5DeepWeightDrawSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t item,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV5FoldChallengeDrawSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t fold,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV5QueryIndexDrawSplitRap(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t query,
    const V5FirstUniformSplitRapProof& proof,
    std::string* why = nullptr);

struct V5QueryIndexLeafSplitRapProofV1 {
    uint16_t version{1};
    uint32_t leaf_ordinal{0};
    uint32_t lane{0};
    uint32_t first_query{0};
    uint256 proof_statement{};
    std::vector<uint32_t> queries;
    std::vector<uint32_t> proved_indices;
    std::vector<uint32_t> v5_semantic_rows;
    std::vector<V5FirstUniformSplitRapProof> query_proofs;
    uint32_t proof_owned_v5_cells{0};
    uint32_t recursively_consumed_v5_cells{0};
    bool full_304_transcript{false};
};

struct V5QueryIndexLeafSplitRapProveResultV1 {
    bool ok{false};
    std::string note;
    V5QueryIndexLeafSplitRapProofV1 proof;
};

[[nodiscard]] V5QueryIndexLeafSplitRapProveResultV1
ProveV5QueryIndexLeafSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t leaf_ordinal);

[[nodiscard]] bool VerifyV5QueryIndexLeafSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t leaf_ordinal,
    const V5QueryIndexLeafSplitRapProofV1& proof,
    std::string* why = nullptr);

/**
 * Complete four-candidate OOD first-valid selector. Candidate SHA/uniform
 * proofs are independently verified and their canonical Fp3 exports are
 * equality-bound into this selector AIR. The selector proves:
 *
 *  - canonical field conversion for all four candidates;
 *  - z1 nonzero in extension coordinates and first-valid over candidates 0/1;
 *  - z2 nonzero, distinct from selected z1, and first-valid over 2/3;
 *  - selected candidate index/value and three exact normalized-V5 rows.
 *
 * This is proof-owned local closure only. It is not a recursive receipt and
 * cannot confer production authority.
 */
struct V5OodPointSelectorWitnessV1 {
    bool valid{false};
    std::string note;
    uint32_t lane{0};
    uint32_t point{0};
    std::array<std::array<Fp3, 3>, 4> candidates{};
    std::array<uint8_t, 4> nonzero{};
    std::array<uint8_t, 4> distinct_from_z1{};
    uint32_t selected_candidate{0};
    std::array<Fp3, 3> selected_output{};
    std::array<uint32_t, 3> v5_semantic_rows{};
    uint32_t candidate_column_base{0};
    uint32_t nonzero_column_base{0};
    uint32_t selector_column_base{0};
    uint32_t selected_index_column{0};
    uint32_t selected_output_base{0};
    uint256 selector_statement{};
    uint256 vertical_air_seed{};
    /** Verifier-reconstructed R0 over the exact four candidate rows. */
    uint256 canonical_r0{};
    aq::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
    std::vector<uint32_t> base_column_indices;
};

[[nodiscard]] V5OodPointSelectorWitnessV1
BuildV5OodPointSelectorWitnessV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t point);

struct V5OodPointSplitRapProofV1 {
    uint16_t version{1};
    uint32_t lane{0};
    uint32_t point{0};
    uint32_t selected_candidate{0};
    uint256 proof_statement{};
    std::array<std::array<Fp3, 3>, 4> proved_candidates{};
    std::array<Fp3, 3> proved_v5_exports{};
    std::array<V5FirstUniformSplitRapProof, 4> candidate_proofs{};
    aq::AirQuotientSplitRapRowsProof selector_quotient;
    uint32_t proof_owned_v5_cells{0};
    uint32_t recursively_consumed_v5_cells{0};
    bool full_304_transcript{false};
};

struct V5OodPointSplitRapProveResultV1 {
    bool ok{false};
    std::string note;
    V5OodPointSplitRapProofV1 proof;
};

[[nodiscard]] V5OodPointSplitRapProveResultV1
ProveV5OodPointSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t point);

[[nodiscard]] bool VerifyV5OodPointSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t point,
    const V5OodPointSplitRapProofV1& proof,
    std::string* why = nullptr);

inline constexpr uint32_t kV5TranscriptVerticalLeafCountV1 = 57;
inline constexpr uint32_t kV5TranscriptShaCallCountV1 = 296;
inline constexpr uint32_t kV5TranscriptLaneSeedFanoutCountV1 = 2;
inline constexpr uint32_t kV5TranscriptNonQueryProofAttachmentCountV1 = 14;
inline constexpr uint32_t kV5TranscriptLocalProofAttachmentCountV1 =
    kV5TranscriptNonQueryProofAttachmentCountV1 +
    kV5TranscriptVerticalLeafCountV1;
inline constexpr uint32_t kV5TranscriptLocalProofOwnedCellsV1 = 42;
inline constexpr uint32_t kV5TranscriptWithQueryProofOwnedCellsV1 = 298;
inline constexpr uint32_t kV5TranscriptAirQuotientPendingCellsV1 = 6;
inline constexpr uint32_t kV5QueryIndexLeafMaxQueriesV1 = 21;
inline constexpr size_t kV5TranscriptLeafProofMaxBytesV1 =
    aq::kAirQuotientSplitRapRowsMaxProofBytesHard;
inline constexpr size_t kV5TranscriptQueryLeafProofMaxBytesV1 =
    kV5QueryIndexLeafMaxQueriesV1 *
        kV5TranscriptLeafProofMaxBytesV1 +
    1024 * 1024;
inline constexpr bool kV5QueryIndexSplitRapPromotedV1 = true;
inline constexpr size_t kV5TranscriptOodProofMaxBytesV1 =
    5 * kV5TranscriptLeafProofMaxBytesV1 +
    1024 * 1024;
inline constexpr size_t kV5TranscriptAttachmentBundleMaxBytesV1 =
    10 * kV5TranscriptLeafProofMaxBytesV1 +
    4 * kV5TranscriptOodProofMaxBytesV1 +
    kV5TranscriptVerticalLeafCountV1 *
        kV5TranscriptQueryLeafProofMaxBytesV1 +
    1024 * 1024;

enum class V5TranscriptLeafProofKindV1 : uint8_t {
    BatchCoefficientSplitRap = 1,
    FirstUniformSplitRap = BatchCoefficientSplitRap,
    OodPointSplitRap = 2,
    DeepWeightSplitRap = 3,
    FoldChallengeSplitRap = 4,
    QueryIndexLeafSplitRap = 5,
};

/** Canonical placement of one bounded SHA leaf in the 30-parent schedule. */
struct V5TranscriptLeafScheduleV1 {
    uint32_t leaf_ordinal{0};
    uint32_t parent_shard{0};
    uint32_t leaf_in_parent{0};
    uint32_t compression_blocks{0};
    uint32_t consumer_source_edges{0};
    uint256 schedule_statement{};
    std::vector<uint32_t> call_ordinals;
    /** Sorted, unique semantic rows touched by at least one source call. */
    std::vector<uint32_t> consumer_semantic_rows;

    bool operator==(const V5TranscriptLeafScheduleV1&) const = default;
};

/**
 * Exact transitive source mapping for one V5 semantic consumer cell.
 *
 * A typed draw may span multiple SHA calls and, in general, multiple bounded
 * leaves. The parallel source-call/source-leaf arrays preserve that fact
 * instead of assigning the cell to an arbitrary leaf.
 */
struct V5TranscriptConsumerLeafBindingV1 {
    uint32_t semantic_row{0};
    ChallengeFeedbackFamily family{
        ChallengeFeedbackFamily::AirQuotient};
    uint32_t lane{0};
    uint32_t item_index{0};
    uint32_t coordinate{0};
    V5EquationConsumer consumer{
        V5EquationConsumer::PerPointIdentity};
    uint32_t source_call_count{0};
    std::array<uint32_t, 8> source_call_ordinals{};
    std::array<uint32_t, 8> source_leaf_ordinals{};
    uint32_t dependency_lane_seed_call{UINT32_MAX};
    uint32_t dependency_lane_seed_leaf{UINT32_MAX};

    bool operator==(
        const V5TranscriptConsumerLeafBindingV1&) const = default;
};

/**
 * One lane seed digest fans eight words into the same 146 downstream calls.
 * The target-leaf vector is positionally parallel to target_call_ordinals.
 */
struct V5TranscriptLaneSeedFanoutV1 {
    uint32_t lane{0};
    uint32_t source_call_ordinal{0};
    uint32_t source_leaf_ordinal{0};
    std::array<uint64_t, 8> word_link_ids{};
    std::vector<uint32_t> target_call_ordinals;
    std::vector<uint32_t> target_leaf_ordinals;

    bool operator==(
        const V5TranscriptLaneSeedFanoutV1&) const = default;
};

/**
 * One canonical, byte-bounded proof attachment.
 *
 * `proof_owned_semantic_rows` may be counted only after the nested canonical
 * proof codec round-trips and the application verifier replays the public
 * child inputs, reconstructs its CS, verifies the proof, and checks these
 * exact rows against the leaf schedule. No recursive-consumption field is
 * promotable in V1.
 */
struct V5TranscriptLeafProofAttachmentV1 {
    uint16_t version{1};
    uint32_t leaf_ordinal{0};
    V5TranscriptLeafProofKindV1 kind{
        V5TranscriptLeafProofKindV1::BatchCoefficientSplitRap};
    uint32_t lane{0};
    /** Batch item for kind 1, OOD point for kind 2. */
    uint32_t batch_item{0};
    uint256 proof_statement{};
    std::vector<uint32_t> proof_owned_semantic_rows;
    std::vector<unsigned char> proof_bytes;
    uint32_t recursively_consumed_cells{0};

    bool operator==(
        const V5TranscriptLeafProofAttachmentV1&) const = default;
};

/**
 * Canonical V1 attachment envelope for the full V5 transcript inventory.
 *
 * All 57 leaves and all 304 source bindings are present even when a proof is
 * not attached. Reusable attachments close both canonical batch items and
 * both complete OOD first-valid points, both DEEP weights, the canonical
 * fold challenge, and all 256 power-of-two query indices. Canonical query
 * leaves pack up to 21 independently verified query relations. These paths
 * own at most 298/304 transcript cells; the six AirQuotient cells remain
 * separate. This is deliberately not a recursion receipt.
 */
struct V5TranscriptProofAttachmentBundleV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint256 source_plan_statement{};
    uint256 public_schedule_statement{};
    uint256 bundle_statement{};
    uint32_t vertical_leaves{0};
    uint32_t sha256d_calls{0};
    uint32_t semantic_cells{0};
    uint32_t lane_seed_fanouts{0};
    uint32_t proof_attached_leaves{0};
    uint32_t proof_owned_cells{0};
    uint32_t algebraically_bound_output_cells{0};
    uint32_t recursively_consumed_cells{0};
    uint32_t pending_cells{0};
    uint64_t encoded_proof_bytes{0};
    bool exact_leaf_call_partition{false};
    bool exact_consumer_source_binding{false};
    bool exact_lane_seed_fanouts{false};
    bool attached_proofs_publicly_verified{false};
    bool all_57_leaf_proofs_attached{false};
    bool recursive_consumption_complete{false};
    bool production_authority_ready{false};
    std::vector<V5TranscriptLeafScheduleV1> leaves;
    std::vector<V5TranscriptConsumerLeafBindingV1> consumers;
    std::array<V5TranscriptLaneSeedFanoutV1, 2> fanouts{};
    std::vector<V5TranscriptLeafProofAttachmentV1> proofs;
};

[[nodiscard]] V5TranscriptProofAttachmentBundleV1
BuildV5TranscriptProofAttachmentBundleV1(
    const V5FullTranscriptWitnessShardPlan& plan);

/**
 * Verify every attached proof from the checked public child inputs. An empty
 * canonical bundle is valid schedule state but owns zero cells.
 */
[[nodiscard]] bool VerifyV5TranscriptProofAttachmentBundleV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why = nullptr);

/**
 * Attach the currently executable first-uniform Split-RAP proof after
 * verification. The resulting bundle owns exactly its three algebraically
 * constrained V5 exports and still consumes zero recursive children.
 */
[[nodiscard]] bool AttachV5FirstUniformSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5FirstUniformSplitRapProof& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why = nullptr);

[[nodiscard]] bool AttachV5BatchCoefficientDrawSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t lane,
    uint32_t batch_item,
    const V5FirstUniformSplitRapProof& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why = nullptr);

[[nodiscard]] bool AttachV5OodPointSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t lane,
    uint32_t point,
    const V5OodPointSplitRapProofV1& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why = nullptr);

[[nodiscard]] bool AttachV5DeepWeightSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t lane,
    uint32_t item,
    const V5FirstUniformSplitRapProof& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why = nullptr);

[[nodiscard]] bool AttachV5FoldChallengeSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    uint32_t lane,
    uint32_t fold,
    const V5FirstUniformSplitRapProof& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why = nullptr);

[[nodiscard]] bool AttachV5QueryIndexLeafSplitRapV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5QueryIndexLeafSplitRapProofV1& proof,
    V5TranscriptProofAttachmentBundleV1& bundle,
    std::string* why = nullptr);

/** Canonical bounded envelope; the 57-leaf schedule is reconstructed from
 * `plan`, so only proof attachments are carried on wire. */
[[nodiscard]] size_t SerializeV5TranscriptProofAttachmentBundleV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptProofAttachmentBundleV1& bundle,
    std::vector<unsigned char>& out);

[[nodiscard]] std::optional<V5TranscriptProofAttachmentBundleV1>
DeserializeV5TranscriptProofAttachmentBundleV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const std::vector<unsigned char>& in);

/**
 * Fail-closed local closure of the complete V5 SHA transcript inventory.
 *
 * The 298-cell attachment bundle and the six-cell same-parent AIR-lambda
 * SHA proof are verified against the same child, seed, public plan and
 * semantic boundary. Their semantic-row sets must be a disjoint exact
 * partition of all 304 consumers.
 *
 * This is deliberately not a recursive receipt: the normalized parent has
 * not verified any of these proof leaves. `normalized_recursive_cells` and
 * `direct_v6_feedback_cells` therefore remain zero.
 */
inline constexpr uint32_t kV5UnifiedShaReceiptMagicV1 =
    0x31525556u; // 'VUR1'
inline constexpr size_t
    kV5UnifiedShaAirProofMaxBytesV1 =
        8 * kRCFriMaxProofBytesHard;
inline constexpr size_t
    kV5UnifiedShaAttachmentMaxBytesV1 =
        size_t{1024} * 1024 * 1024;
inline constexpr size_t
    kV5UnifiedShaReceiptMaxBytesV1 =
        kV5UnifiedShaAttachmentMaxBytesV1 +
        kV5UnifiedShaAirProofMaxBytesV1 + 1024;

struct V5UnifiedShaReceiptV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint256 source_plan_statement{};
    uint256 public_schedule_statement{};
    uint256 semantic_boundary_commitment{};
    uint256 airq_combined_air_seed{};
    uint256 receipt_commitment{};
    uint32_t semantic_cells{0};
    uint32_t split_rap_local_cells{0};
    uint32_t same_parent_sha_cells{0};
    uint32_t proof_owned_local_cells{0};
    uint32_t normalized_recursive_cells{0};
    uint32_t direct_v6_feedback_cells{0};
    uint32_t pending_normalized_recursive_cells{0};
    uint64_t encoded_attachment_bytes{0};
    uint64_t encoded_airq_proof_bytes{0};
    bool one_child_seed_and_plan{false};
    bool exact_disjoint_304_coverage{false};
    bool nested_codecs_canonical{false};
    bool attached_proofs_publicly_verified{false};
    bool airq_sha_proof_publicly_verified{false};
    bool complete_local_sha_transcript_proof{false};
    bool normalized_recursive_consumption_complete{false};
    bool v6_challenges_drive_v5_equations{false};
    bool production_authority_ready{false};
    std::vector<unsigned char> attachment_bundle_bytes;
    std::vector<unsigned char> airq_proof_bytes;
};

[[nodiscard]] V5UnifiedShaReceiptV1
BuildV5UnifiedShaReceiptV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5TranscriptProofAttachmentBundleV1& attachments,
    const aq::AirQuotientProof<Fp3>& airq_sha_proof);

[[nodiscard]] bool VerifyV5UnifiedShaReceiptV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5UnifiedShaReceiptV1& receipt,
    std::string* why = nullptr);

[[nodiscard]] size_t SerializeV5UnifiedShaReceiptV1(
    const V5UnifiedShaReceiptV1& receipt,
    std::vector<unsigned char>& out);

[[nodiscard]] std::optional<V5UnifiedShaReceiptV1>
DeserializeV5UnifiedShaReceiptV1(
    const V5FullTranscriptWitnessShardPlan& plan,
    const std::vector<unsigned char>& in);

/**
 * Additive V6 challenge-source selector.
 *
 * LegacyAlgHash names the existing V6 transcript and is intentionally not
 * accepted by the SHA compatibility adapter.  UnifiedV5ShaReceipt selects
 * the versioned, publicly verified 304-cell V5 SHA256d receipt.  Keeping the
 * domains distinct prevents an AlgHash output stream from being substituted
 * for the SHA-derived values consumed by normalized V5.
 */
enum class V6ChallengeSourceDomainV1 : uint8_t {
    LegacyAlgHash = 1,
    UnifiedV5ShaReceipt = 2,
};

enum V6ShaCompatibilityColumnV1 : uint32_t {
    kV6ShaCompatibilityActive = 0,
    kV6ShaCompatibilityFamily,
    kV6ShaCompatibilityLane,
    kV6ShaCompatibilityItem,
    kV6ShaCompatibilityCoordinate,
    kV6ShaCompatibilityConsumer,
    kV6ShaCompatibilityExpected,
    /** Locally verified output of the unified V5 SHA receipt. */
    kV6ShaCompatibilityReceiptOutput,
    /** The value literally supplied to the normalized V5 equation. */
    kV6ShaCompatibilityNormalizedInput,
    kV6ShaCompatibilityColumns,
};

struct V6ShaCompatibilityCellV1 {
    uint32_t ordinal{0};
    ChallengeFeedbackFamily family{
        ChallengeFeedbackFamily::AirQuotient};
    uint32_t lane{0};
    uint32_t item_index{0};
    uint32_t coordinate{0};
    V5EquationConsumer consumer{
        V5EquationConsumer::PerPointIdentity};
    gkr_field::Fp receipt_output{0};
    gkr_field::Fp normalized_v5_input{0};

    bool operator==(
        const V6ShaCompatibilityCellV1&) const = default;
};

/**
 * Versioned SHA-domain migration seam for V6 -> normalized V5 feedback.
 *
 * The builder first publicly verifies the complete unified SHA receipt
 * against the exact child, seed and public transcript plan.  It then places
 * the receipt's 304 ordered outputs in one witness column and aliases them,
 * row for row, into the normalized-V5 consumer-input column.  Verifier-fixed
 * columns pin the exact family/lane/item/coordinate/consumer/value schedule.
 *
 * This establishes 304/304 *local direct* feedback cells.  It deliberately
 * establishes 0/304 normalized-recursive cells because the normalized parent
 * has not yet verified the receipt children in AIR.  It is therefore neither
 * a recursive receipt nor production consensus authority.
 */
struct V6ShaCompatibilityModeV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    V6ChallengeSourceDomainV1 challenge_source_domain{
        V6ChallengeSourceDomainV1::UnifiedV5ShaReceipt};
    uint256 child_fs_seed{};
    uint256 source_plan_statement{};
    uint256 public_schedule_statement{};
    uint256 semantic_boundary_commitment{};
    uint256 unified_receipt_commitment{};
    uint256 ordered_output_commitment{};
    uint256 compatibility_statement{};
    uint32_t semantic_cells{0};
    uint32_t local_direct_feedback_cells{0};
    uint32_t normalized_recursive_cells{0};
    uint32_t pending_normalized_recursive_cells{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    bool unified_receipt_publicly_verified{false};
    bool exact_schedule_and_order{false};
    bool exact_statement_equality{false};
    bool exact_seed_equality{false};
    bool receipt_outputs_drive_normalized_v5_equations{false};
    bool legacy_alghash_semantics_unchanged{true};
    bool alghash_domain_substitution_rejected{false};
    bool normalized_recursive_consumption_complete{false};
    bool production_authority_ready{false};
    std::vector<V6ShaCompatibilityCellV1> cells;
    aq::AirConstraintSystem<Fp3> constraint_system;
    std::vector<std::vector<Fp3>> witness_columns;
};

[[nodiscard]] V6ShaCompatibilityModeV1
BuildV6ShaCompatibilityModeV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5UnifiedShaReceiptV1& receipt,
    V6ChallengeSourceDomainV1 source_domain =
        V6ChallengeSourceDomainV1::UnifiedV5ShaReceipt);

[[nodiscard]] bool VerifyV6ShaCompatibilityModeV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5UnifiedShaReceiptV1& receipt,
    const V6ShaCompatibilityModeV1& compatibility,
    std::string* why = nullptr);

struct V5UnifiedShaArityFourNodeV1 {
    uint32_t level{0};
    uint32_t ordinal{0};
    uint32_t child_count{0};
    std::array<uint32_t, 4> child_ordinal{};
    std::array<uint8_t, 4> child_active{};
    std::array<uint256, 4> child_commitment{};
    uint256 node_commitment{};
    bool operator==(
        const V5UnifiedShaArityFourNodeV1&) const = default;
};

/**
 * Exact arity-four aggregation schedule after the 304-cell local receipt is
 * closed. There are 58 leaf children: 57 canonical transcript leaves plus
 * the AIR-lambda Split-RAP child. Padding slots use domain-bound canonical
 * empty commitments and are explicitly excluded by child_count.
 *
 * This planner never promotes proof availability into normalized recursive
 * consumption. The remaining executable obligation is a normalized parent
 * that byte/field-decodes and verifies every listed child proof.
 */
struct V5UnifiedShaRecursivePlanV1 {
    uint16_t version{1};
    bool valid{false};
    std::string note;
    uint256 receipt_commitment{};
    uint256 airq_split_rap_statement{};
    uint256 recursive_schedule_commitment{};
    uint32_t transcript_leaf_children{0};
    uint32_t airq_children{0};
    uint32_t total_leaf_children{0};
    uint32_t aggregation_levels{0};
    uint32_t aggregation_parent_nodes{0};
    uint32_t locally_proof_owned_cells{0};
    uint32_t normalized_recursive_cells{0};
    uint32_t pending_normalized_recursive_cells{0};
    bool exact_arity_four_schedule{false};
    bool canonical_empty_children_domain_bound{false};
    bool all_child_codecs_durable{false};
    bool airq_split_rap_locally_verified{false};
    bool parent_verifier_air_executable{false};
    bool production_authority_ready{false};
    std::vector<V5UnifiedShaArityFourNodeV1> nodes;
    std::vector<std::string> residuals;
};

[[nodiscard]] V5UnifiedShaRecursivePlanV1
BuildV5UnifiedShaRecursivePlanV1(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const V5FullTranscriptWitnessShardPlan& plan,
    const V5UnifiedShaReceiptV1& receipt,
    const V5AirLambdaSplitRapProofV1& airq_split_rap);

[[nodiscard]] V5ShaProducerPlan AssessV5ShaProducerPlan(
    const SameTraceComposition& composition,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed);

/**
 * Materialize all 304 normalized-V5 FS consumer cells from the already
 * verified/replayed V5 public inputs. The 304 values occupy one proof-owned
 * time-multiplexed column. Seven verifier-fixed columns pin the exact
 * active/family/lane/item/coordinate/consumer/value schedule, and AIR
 * equality binds each witness cell to that public SHA-derived boundary.
 *
 * This deliberately does NOT assert that V6's algebraic transcript outputs
 * equal the V5 SHA transcript.
 */
[[nodiscard]] V5SemanticMaterialization
BuildV5SemanticMaterialization(
    const SameTraceComposition& composition);

[[nodiscard]] bool VerifyV5SemanticMaterialization(
    const SameTraceComposition& composition,
    const uint256& public_boundary_commitment,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why = nullptr);

/**
 * Reconstruct the canonical V6 statement from two ordered normalized V5 lane
 * public inputs.  No opaque child-pin or host-report field is accepted.
 */
[[nodiscard]] v6::Program BuildProgramFromV5LanePublicInputs(
    const std::vector<ar::ChildPublicInputs>& lane_pis,
    const std::array<uint8_t, 32>& public_statement_sha256d,
    TranscriptScope scope,
    std::string* why = nullptr);

/**
 * Verify one dual-Q128/V5 child, replay its finite V5 transcript, construct
 * the normalized V5 verifier witness, publish its proof-derived outputs, and
 * compose V6 by literal same-column aliasing.
 */
[[nodiscard]] SameTraceComposition BuildSameTraceComposition(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    const std::array<uint8_t, 32>& public_statement_sha256d,
    TranscriptScope scope = TranscriptScope::FullTranscript,
    const ar::VerifierAirFamilies& families = {});

struct Shape {
    bool valid{false};
    std::string note;
    uint32_t v5_rows{0};
    uint32_t v6_rows{0};
    uint32_t aligned_rows{0};
    uint32_t v5_columns{0};
    uint32_t export_and_selector_columns{0};
    uint32_t combined_columns{0};
    uint32_t v5_constraints{0};
    uint32_t combined_constraints{0};
    uint64_t combined_cells{0};
    uint32_t proof_derived_payload_cells{0};
    uint32_t row_root_payload_cells_directly_aliased{0};
    uint32_t transcript_payload_cells_directly_aliased{0};
    uint32_t selector_columns{0};
};

/** Exact allocation/constraint count without allocating the combined witness. */
[[nodiscard]] Shape MeasureSameTraceComposition(
    const std::vector<ar::ChildPublicInputs>& lane_pis,
    const std::array<uint8_t, 32>& public_statement_sha256d,
    TranscriptScope scope = TranscriptScope::FullTranscript,
    const ar::VerifierAirFamilies& families = {});

inline constexpr bool kNormalizedV5EightLaneExportBusExecutable = true;
inline constexpr bool kV5V6LiteralSameTraceAliasExecutable = true;
inline constexpr bool kV5V6FullTranscriptPayloadBusExecutable = true;
inline constexpr bool kV5ShaPublicBoundaryMaterializationExecutable = true;
inline constexpr bool kV5V6CommittedFeedbackBusExecutable = true;
inline constexpr bool
    kV5V6NormalizedFeedbackReceiptBindingExecutable = true;
inline constexpr bool
    kV5V6NormalizedFeedbackRecursiveOwnershipReady = false;
inline constexpr uint32_t kV5V6CommittedFeedbackAliasCells =
    kV5SemanticConsumerCells;
inline constexpr uint32_t kV5V6RecursiveShaDerivationCells = 6;
inline constexpr uint32_t kV5V6AlgebraicChallengeDerivationCells = 0;
inline constexpr bool kV6ChallengesDriveNormalizedV5Equations = false;
inline constexpr bool kV5ShaTranscriptEquationsInCombinedAir = false;
inline constexpr bool kV5V6CombinedAuthorityReady = false;

static_assert(kNormalizedV5EightLaneExportBusExecutable);
static_assert(kV5V6LiteralSameTraceAliasExecutable);
static_assert(kV5V6FullTranscriptPayloadBusExecutable);
static_assert(kV5ShaPublicBoundaryMaterializationExecutable);
static_assert(kV5V6CommittedFeedbackBusExecutable);
static_assert(kV5V6NormalizedFeedbackReceiptBindingExecutable);
static_assert(!kV5V6NormalizedFeedbackRecursiveOwnershipReady);
static_assert(kV5V6CommittedFeedbackAliasCells ==
              kV5SemanticConsumerCells);
static_assert(kV5V6RecursiveShaDerivationCells == 6);
static_assert(kV5V6AlgebraicChallengeDerivationCells == 0);
static_assert(!kV6ChallengesDriveNormalizedV5Equations);
static_assert(!kV5ShaTranscriptEquationsInCombinedAir);
static_assert(!kV5V6CombinedAuthorityReady);

} // namespace matmul::v4::rc::stage3_v5_v6_bus

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V5_V6_BUS_H
