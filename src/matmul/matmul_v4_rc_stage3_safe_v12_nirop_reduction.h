// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_NIROP_REDUCTION_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_NIROP_REDUCTION_H

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_global_soundness_ledger.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_fs_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

/**
 * Executable V12 common-commitment join and fail-closed NIROP ledger.
 *
 * The two Q96 transcripts remain distinct SAFE instances.  They are joined
 * through one verifier-derived parent seed that commits to:
 *
 *   - the application statement;
 *   - the immutable verifier/program table;
 *   - the common trace;
 *   - both lanes' shape, row, OOD-evaluation and fold commitments.
 *
 * A single nonce is absorbed by both transcripts and must satisfy the
 * field-native g=20 tax.  Thus changing only one lane's proof commitments or
 * nonce cannot preserve an already accepted transcript receipt.
 *
 * The numeric ledger encodes the conditional hybrid expression
 *
 *   eps_global <= S * (
 *       2^g * ((17/32)^Q * (17/32)^Q)
 *       + 2^-128
 *       + eps_SAFE/NIROP
 *   ),
 *
 * with shipped Q=96, g=20 and S=37,488,397.  The lane terms multiply only
 * under the separately recorded independence premise; common binding and
 * NIROP terms add; the regrind and site factors are each applied once.
 *
 * This file deliberately does not turn the conditional expression into a
 * security certificate.  The root-to-trace equality AIR is executable, but
 * its normalized-recursive consumption, the concrete SAFE reductions,
 * sole-query-source tax integration and recursively enforced site manifest
 * remain explicit false premises.
 */
namespace matmul::v4::rc::stage3_safe_v12_nirop_reduction {

namespace gf = gkr_field;
namespace ah = alg_hash;
namespace aht = alg_hash_typed;
namespace safe = safe_v12;
namespace fsair = stage3_safe_v12_fs_air;
namespace scenarios = soundness_scenarios;
namespace gsl = global_soundness_ledger;
namespace aq = air_quotient;

inline constexpr uint32_t kProtocolVersionV12 = 12;
inline constexpr uint32_t kQueriesPerLaneV12 =
    fsair::kQueriesPerLaneV12;
inline constexpr uint32_t kLaneCountV12 =
    fsair::kFriLaneCountV12;
inline constexpr uint32_t kTaxedGrindBitsV12 =
    kRCFri3AlgTaxedQGrindBits;
inline constexpr uint64_t kProductionProofSitesV12 =
    gsl::kCanonicalProductionSites;
inline constexpr uint32_t kCommonBindingBitsV12 = 128;
inline constexpr uint32_t kConditionalSafeNiropBitsV12 = 128;
inline constexpr uint32_t kV1TargetBitsV12 =
    gsl::kV1ConsensusSecurityClassBits;
inline constexpr gf::Fp kCommonBindingMagicV12 =
    UINT64_C(0x4254585631324a4e); // "BTXV12JN"
inline constexpr gf::Fp kTraceEqualityMagicV12 =
    UINT64_C(0x4254585631325452); // "BTXV12TR"

static_assert(kQueriesPerLaneV12 == 96);
static_assert(kLaneCountV12 == 2);
static_assert(kTaxedGrindBitsV12 == 20);
static_assert(kProductionProofSitesV12 == 37'488'397ULL);

struct CommonCommitmentsV12 {
    ah::Digest statement{};
    ah::Digest program{};
    ah::Digest trace{};

    friend bool operator==(
        const CommonCommitmentsV12&,
        const CommonCommitmentsV12&) = default;
};

/**
 * Equality cells exported by each lane's recursive child.  These are proof
 * witness cells, not independent public statements and not preprocessed
 * columns.
 */
struct LaneCommonClaimV12 {
    ah::Digest statement{};
    ah::Digest program{};
    ah::Digest trace{};

    friend bool operator==(
        const LaneCommonClaimV12&,
        const LaneCommonClaimV12&) = default;
};

/**
 * Shape fields copied out of each proof lane.  The canonical values are
 * verifier-derived from ManifestV12; the two copies remain ordinary proof
 * witness cells and are equality-constrained to those public values.
 */
struct TraceMetadataV12 {
    uint32_t protocol_version{kProtocolVersionV12};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t quotient_len{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    uint32_t blowup{fsair::kFriBlowupV12};
    uint32_t folds{0};

    friend bool operator==(
        const TraceMetadataV12&,
        const TraceMetadataV12&) = default;
};

struct HybridInputsV12 {
    CommonCommitmentsV12 common{};
    std::array<LaneCommonClaimV12, kLaneCountV12> lane_claim{};
    std::array<TraceMetadataV12, kLaneCountV12>
        lane_trace_metadata{};
    fsair::TranscriptInputsV12 transcript{};
    uint64_t shared_grind_nonce{0};
};

/**
 * A small linear AIR that gives the shared-commitment hybrid concrete cells:
 *
 *  - proof trace and both lane trace aliases equal the one verifier-owned
 *    common trace commitment;
 *  - both proof-owned metadata copies equal the shape-derived public tuple;
 *  - both shape commitments equal one canonical V12 SAFE digest; and
 *  - both Q96 row/Merkle-root copies equal that same common trace
 *    commitment (and therefore each other).
 *
 * Only the common trace, canonical shape digest and shape tuple are
 * preprocessed.  Lane roots, lane metadata and trace aliases never are.
 */
struct TraceRootEqualityAirV12 {
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    TraceMetadataV12 canonical_metadata{};
    ah::Digest canonical_shape_commit{};
    ah::Digest shared_row_root{};
    uint32_t verifier_owned_preprocessed_columns{0};
    uint32_t proof_owned_preprocessed_columns{0};
    uint32_t equality_constraints{0};
    uint32_t constraint_violations{0};
    bool common_trace_aliases_constrained{false};
    bool metadata_aliases_constrained{false};
    bool canonical_shape_aliases_constrained{false};
    bool shared_row_root_constrained{false};
    bool row_root_to_common_trace_constrained{false};
    bool only_verifier_owned_values_preprocessed{false};
    bool valid{false};
    std::string note;
};

struct CommonBindingReceiptV12 {
    aht::RoleV12 binding_role{
        aht::RoleV12::ApplicationStatementCommitment};
    ah::Digest parent_fs_seed{};
    ah::Digest common_statement{};
    ah::Digest common_program{};
    ah::Digest common_trace{};
    std::array<LaneCommonClaimV12, kLaneCountV12> lane_claim{};
    uint32_t proof_dependent_preprocessed_columns{0};
    bool common_cells_canonical{false};
    bool both_lanes_equal_common_cells{false};
    bool proof_bundle_bound_to_parent_seed{false};
    bool transcript_trace_equals_common_trace{false};
    bool both_lanes_use_shared_nonce{false};
    bool valid{false};
    std::string note;

    friend bool operator==(
        const CommonBindingReceiptV12&,
        const CommonBindingReceiptV12&) = default;
};

struct HybridReceiptV12 {
    CommonBindingReceiptV12 common_binding{};
    TraceRootEqualityAirV12 trace_root_equality_air{};
    fsair::AirWitnessV12 transcript_air{};
    std::vector<gf::Fp> tax_sigma_core;
    ah::Digest tax_sigma{};
    Fri3AlgGrindPredicateAirV1 tax_predicate_air{};
    std::array<std::vector<uint32_t>, kLaneCountV12>
        query_indices{};
    bool manifest_valid{false};
    bool common_binding_valid{false};
    bool trace_root_equality_air_valid{false};
    bool native_air_transcript_valid{false};
    bool typed_lane_domains_distinct{false};
    bool query_vectors_distinct{false};
    bool tax_satisfied{false};
    bool tax_air_constraints_zero{false};
    bool valid{false};
    std::string note;
};

/** Verifier-derived V12 tuple. */
[[nodiscard]] TraceMetadataV12 CanonicalTraceMetadataV12(
    const fsair::ManifestV12& manifest);

/**
 * Derive the only canonical shape commitment. Supplying another typed role
 * is exposed solely so the oracle-role substitution test can construct and
 * reject a real alternate digest.
 */
[[nodiscard]] bool DeriveCanonicalShapeCommitV12(
    const fsair::ManifestV12& manifest,
    aht::RoleV12 role, ah::Digest& shape_commit,
    std::string* why = nullptr);

[[nodiscard]] bool BuildTraceRootEqualityAirV12(
    const fsair::ManifestV12& manifest,
    const CommonCommitmentsV12& common,
    const std::array<LaneCommonClaimV12, kLaneCountV12>&
        lane_claim,
    const std::array<TraceMetadataV12, kLaneCountV12>&
        lane_metadata,
    const fsair::ProofWitnessInputsV12& proof_witness,
    TraceRootEqualityAirV12& out,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateTraceRootEqualityAirV12(
    const fsair::ManifestV12& manifest,
    const CommonCommitmentsV12& common,
    const std::array<LaneCommonClaimV12, kLaneCountV12>&
        lane_claim,
    const std::array<TraceMetadataV12, kLaneCountV12>&
        lane_metadata,
    const fsair::ProofWitnessInputsV12& proof_witness,
    const TraceRootEqualityAirV12& air,
    std::string* why = nullptr);

/**
 * Derive the only admissible parent seed.  Supplying another role is useful
 * for adversarial tests, but VerifyHybridV12 always reconstructs the
 * ApplicationStatementCommitment role.
 */
[[nodiscard]] bool DeriveParentFsSeedV12(
    const fsair::ManifestV12& manifest,
    const CommonCommitmentsV12& common,
    const fsair::ProofWitnessInputsV12& proof_witness,
    aht::RoleV12 role, ah::Digest& seed,
    std::string* why = nullptr);

/** Canonical preimage of the one taxed nonce shared by both lanes. */
[[nodiscard]] bool BuildTaxSigmaCoreV12(
    const fsair::ManifestV12& manifest,
    const CommonCommitmentsV12& common,
    const ah::Digest& parent_fs_seed,
    std::vector<gf::Fp>& sigma_core,
    std::string* why = nullptr);

[[nodiscard]] bool CheckSharedGrindNonceV12(
    const std::vector<gf::Fp>& sigma_core, uint64_t nonce,
    ah::Digest* sigma = nullptr);

/**
 * Prover helper.  max_iters=0 uses the bounded production helper's canonical
 * 2^(g+slack) ceiling.  No transcript query is derived until this nonce is
 * copied into both lane preambles.
 */
[[nodiscard]] bool FindSharedGrindNonceV12(
    const std::vector<gf::Fp>& sigma_core, uint64_t& nonce,
    uint64_t max_iters = 0, std::string* why = nullptr);

/** Build and verify the complete executable join receipt. */
[[nodiscard]] bool BuildHybridReceiptV12(
    const fsair::ManifestV12& manifest,
    const HybridInputsV12& inputs,
    HybridReceiptV12& receipt,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateHybridReceiptV12(
    const fsair::ManifestV12& manifest,
    const HybridInputsV12& inputs,
    const HybridReceiptV12& receipt,
    std::string* why = nullptr);

struct ShippedSoundnessReductionV12 {
    uint32_t lanes{0};
    uint32_t queries_per_lane{0};
    uint32_t total_queries{0};
    uint32_t grind_bits{0};
    uint64_t proof_sites{0};
    double site_union_bits{0.0};
    double proximity_ratio{0.0};
    double proximity_bits_per_query{0.0};

    long double lane_failure_probability{0.0L};
    long double multiplicative_pair_failure_probability{0.0L};
    long double grind_amplified_pair_failure_probability{0.0L};
    long double common_binding_failure_probability{0.0L};
    long double conditional_safe_nirop_failure_probability{0.0L};
    long double per_site_conditional_failure_probability{0.0L};
    long double global_conditional_failure_probability{0.0L};

    double lane_proximity_bits{0.0};
    double multiplicative_pair_bits{0.0};
    double pair_after_single_grind_bits{0.0};
    double common_binding_bits{0.0};
    double conditional_safe_nirop_bits{0.0};
    double per_site_conditional_bits{0.0};
    double global_conditional_bits{0.0};

    bool parameters_read_from_shipped_construction{false};
    bool proof_site_arithmetic_manifest_valid{false};
    bool proof_site_upper_bound_recursively_enforced{false};
    bool common_transcript_join_executable{false};
    bool common_trace_root_equality_air_executable{false};
    bool common_trace_root_equality_recursively_consumed{false};
    bool lane_domains_and_tags_distinct{false};
    bool lane_query_vectors_distinct{false};
    bool shared_nonce_tax_executable{false};
    bool shared_nonce_tax_is_sole_query_entropy_source{false};
    bool lane_independence_reduction_complete{false};
    bool common_commitment_binding_reduction_complete{false};
    bool concrete_safe_nirop_reduction_complete{false};
    bool multiplicative_then_additive_expression_machine_checked{false};
    bool conditional_numeric_v1_target_met{false};
    bool nirop_reduction_certified{false};
    std::string exact_expression;
    std::vector<std::string> residual_premises;
    std::string note;
};

/**
 * Evaluate the exact conditional dual-lane expression and every prerequisite.
 * A valid executable receipt is required, but it is not confused with the
 * still-open cryptographic reductions.
 */
[[nodiscard]] ShippedSoundnessReductionV12
AssessShippedSoundnessReductionV12(
    const fsair::ManifestV12& manifest,
    const HybridInputsV12& inputs,
    const HybridReceiptV12& receipt);

inline constexpr bool
    kDualQ96CommonTranscriptJoinExecutableV12 = true;
inline constexpr bool
    kDualQ96SharedNonceTaxPredicateExecutableV12 = true;
inline constexpr bool
    kDualQ96SharedTraceRootEqualityAirExecutableV12 = true;
inline constexpr bool
    kDualQ96CommonCommitmentHybridReductionCertifiedV12 = false;
inline constexpr bool
    kDualQ96NiropReductionCertifiedV12 = false;
inline constexpr bool kDualQ96GlobalReductionCertifiedV12 = false;
inline constexpr bool kDualQ96AuthorityReadyV12 =
    kDualQ96CommonTranscriptJoinExecutableV12 &&
    kDualQ96SharedNonceTaxPredicateExecutableV12 &&
    kDualQ96CommonCommitmentHybridReductionCertifiedV12 &&
    kDualQ96NiropReductionCertifiedV12 &&
    kDualQ96GlobalReductionCertifiedV12;

static_assert(!kDualQ96AuthorityReadyV12);

} // namespace matmul::v4::rc::stage3_safe_v12_nirop_reduction

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_NIROP_REDUCTION_H
