// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_SEMANTIC_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_SEMANTIC_PRODUCT_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace matmul::v4::rc::fixed_program_semantic_product {

namespace ha = stage3_hash_air;
namespace sites = soundness_scenarios;
using gkr_field::Fp3;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint16_t kWitnessVersionV2 = 2;
inline constexpr uint32_t kFamilyCountV1 = 11;
inline constexpr uint32_t kMaxBoundariesPerChildV1 =
    ha::kFixedProgramVerticalSemanticInstances;
/** SHA witness-boundary children use linked auxiliary sinks; thirty-two
 * sources plus linked and explicit power-of-two padding sinks fit the
 * canonical 64-instance schedule.  ChaCha uses the single-instance private
 * split-RAP construction below instead of this batching limit. */
inline constexpr uint32_t kMaxWitnessSourcesPerChildV2 = 32;

/**
 * These are exactly the eleven fixed SHA/XOF/ChaCha sites which remain
 * partial in ProductionFamilyProgramSourceV1.  Array order is consensus
 * metadata: the verifier regenerates it and never accepts a prover-selected
 * family order.
 */
using FamilyPayloadV1 = std::variant<
    ha::ShaManifest,
    ha::CounterXofManifest,
    ha::ChaChaConsumptionManifest>;

struct FamilyInputV1 {
    sites::ProductionProofSiteKind kind{
        sites::ProductionProofSiteKind::EpisodeScaleSha};
    FamilyPayloadV1 payload{};
};

using FamilyInputsV1 = std::array<FamilyInputV1, kFamilyCountV1>;

struct FamilyStatementV1 {
    sites::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    RCStage3RelationEndpoint endpoint{};
    ha::ProgramKind program_kind{};
    uint32_t family_ordinal{0};
    uint32_t program_boundary_begin{0};
    uint32_t boundary_count{0};
    uint32_t output_logical_rows{0};
    uint32_t output_padded_rows{0};
    uint256 typed_domain{};
    uint256 manifest_commitment{};
    uint256 immutable_schedule_commitment{};
    /** Root of final words which are public boundary pins in this V1 child. */
    uint256 boundary_pinned_output_root{};

    bool operator==(const FamilyStatementV1&) const = default;
};

struct ProductManifestV1 {
    uint16_t version{kVersionV1};
    std::array<FamilyStatementV1, kFamilyCountV1> families{};
    uint32_t sha_boundary_count{0};
    uint32_t chacha_boundary_count{0};
    uint256 production_site_manifest_commitment{};
    uint256 exact_all_instance_root{};
    uint256 statement_commitment{};

    bool canonical_family_order{false};
    bool immutable_schedule_derived{false};
    bool opcode_selector_children_required{false};
    bool internal_ssa_copy_children_required{false};
    bool boundary_public_pins_required{false};
    /** Exact only relative to the caller's eleven typed manifests. */
    bool exact_input_manifest_aggregation{false};
    /** False until those manifests are derived from production role proofs. */
    bool production_manifest_derived{false};
    bool production_all_instance_aggregation{false};
    bool public_boundary_values{false};
    bool proof_owned_output_exports{false};
    bool caller_manifests_bound_to_role_proofs{false};
    /** False until the normalized V11 parent verifies every child below. */
    bool recursive_child_consumed{false};
    bool semantic_closure{false};
    bool production_authority{false};

    bool operator==(const ProductManifestV1&) const = default;
};

struct ProgramBatchProofV1 {
    ha::ProgramKind program_kind{};
    uint32_t boundary_count{0};
    std::vector<ha::FixedProgramVerticalProvenanceAirProof> children;
};

struct ProductProofV1 {
    uint16_t version{kVersionV1};
    ProductManifestV1 manifest;
    ProgramBatchProofV1 sha;
    ProgramBatchProofV1 chacha;
    bool valid{false};
    std::string note;
};

/**
 * A typed handle to ordinary epoch-R0 cells in one witness-boundary child.
 * This is deliberately not described as a value-vector Merkle root: the
 * binding object is the child's complete ordered R0 row commitment plus the
 * canonical cell schedule hashed below.  A recursive consumer can therefore
 * open/equality-link the exact cells without trusting caller-supplied values.
 */
struct FamilyExportFragmentV2 {
    uint32_t child_ordinal{0};
    uint32_t family_ordinal{0};
    uint32_t family_boundary_begin{0};
    uint32_t source_instance_begin{0};
    uint32_t source_instance_count{0};
    uint64_t input_cell_count{0};
    uint64_t output_cell_count{0};
    uint256 typed_input_cell_handle_root{};
    uint256 typed_output_producer_root{};

    bool operator==(const FamilyExportFragmentV2&) const = default;
};

struct FamilyWitnessStatementV2 {
    sites::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    RCStage3RelationEndpoint endpoint{};
    ha::ProgramKind program_kind{};
    uint32_t family_ordinal{0};
    uint32_t boundary_count{0};
    uint32_t fragment_count{0};
    uint256 caller_manifest_commitment{};
    uint256 typed_domain{};
    uint256 proof_owned_input_root{};
    uint256 proof_owned_output_producer_root{};

    bool operator==(const FamilyWitnessStatementV2&) const = default;
};

struct DualFp3ProducerTerminalV2 {
    Fp3 lane1{};
    Fp3 lane2{};

    bool operator==(const DualFp3ProducerTerminalV2& other) const
    {
        return gkr_field::Eq(lane1, other.lane1) &&
            gkr_field::Eq(lane2, other.lane2);
    }
};

struct WitnessChildStatementV2 {
    ha::ProgramKind program_kind{};
    uint32_t child_ordinal{0};
    uint32_t global_source_begin{0};
    uint32_t source_instance_count{0};
    uint32_t sink_instance_count{0};
    uint32_t scheduled_instances{0};
    uint32_t output_event_count{0};
    uint256 public_boundary_statement{};
    uint256 base_row_commitment{};
    DualFp3ProducerTerminalV2 output_producer_terminal{};
    uint256 typed_fragment_root{};
    std::vector<FamilyExportFragmentV2> fragments;

    bool operator==(const WitnessChildStatementV2&) const = default;
};

struct WitnessProductManifestV2 {
    uint16_t version{kWitnessVersionV2};
    uint256 caller_input_statement_commitment{};
    std::array<FamilyWitnessStatementV2, kFamilyCountV1> families{};
    std::vector<WitnessChildStatementV2> children;
    uint256 exact_instance_schedule_root{};
    uint256 statement_commitment{};

    bool canonical_family_order{false};
    bool private_boundary_inputs{false};
    bool private_boundary_outputs{false};
    bool proof_owned_input_exports{false};
    bool proof_owned_output_exports{false};
    bool dual_fp3_external_input_copy_ctl{false};
    bool dual_fp3_output_producer_ctl{false};
    bool auxiliary_sinks_equality_constrained{false};
    bool private_chacha_internal_ssa_ctl{false};
    bool caller_manifests_bound_to_role_proofs{false};
    bool consumer_ctl_linked{false};
    bool recursive_child_consumed{false};
    bool semantic_closure{false};
    bool production_authority{false};

    bool operator==(const WitnessProductManifestV2&) const = default;
};

struct WitnessChildProofV2 {
    WitnessChildStatementV2 statement;
    air_quotient::AirQuotientSplitRapRowsProof quotient;
};

struct WitnessProductProofV2 {
    uint16_t version{kWitnessVersionV2};
    WitnessProductManifestV2 manifest;
    std::vector<WitnessChildProofV2> children;
    bool valid{false};
    std::string note;
};

/**
 * Canonically derive all typed roles, endpoints, program kinds, boundaries,
 * offsets and public-boundary output roots from the eleven typed manifests.
 * The caller manifests are not yet equality-linked to owning role proofs;
 * this is deliberately recorded in ProductManifestV1.
 */
[[nodiscard]] bool BuildProductManifestV1(
    const FamilyInputsV1& inputs,
    ProductManifestV1& out,
    std::string* why = nullptr);

/**
 * Prove every canonical boundary in chunks of at most 63.  Every child is the
 * executable selector/boundary/internal-SSA provenance AIR.  Chunk seeds bind
 * the complete product statement, kind, exact offset and exact count.
 */
[[nodiscard]] bool ProveProductV1(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    ProductProofV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyProductV1(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    const ProductProofV1& proof,
    std::string* why = nullptr);

/**
 * V2 replaces V1's public final-word pins with the existing split-RAP
 * witness-boundary AIR.  Source externals and finals are ordinary R0-bound
 * proof cells.  A dual-Fp3 external-address copy relation makes every use of
 * one canonical private boundary word equal.  Canonical auxiliary sink
 * instances consume every source final word through the witness-boundary
 * dual-Fp3 equality bus, while an additional domain-separated dual-Fp3
 * producer accumulator exports the exact output-cell multiset for a later
 * real consumer.
 *
 * The caller's typed manifests determine only family/count/domain metadata.
 * Their values are not yet equality-linked to the private source cells; that
 * residual and recursive consumption remain explicitly false.
 */
[[nodiscard]] bool ProveWitnessProductV2(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    WitnessProductProofV2& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyWitnessProductV2(
    const FamilyInputsV1& inputs,
    const uint256& fs_seed,
    const WitnessProductProofV2& proof,
    std::string* why = nullptr);

/**
 * Receipt cells must be unreduced canonical u32 base-field representatives.
 * In particular x+p is rejected before field arithmetic can alias it to x.
 */
[[nodiscard]] bool DecodeCanonicalU32V1(
    const Fp3& cell,
    uint32_t& out,
    std::string* why = nullptr);

inline constexpr bool kRecursiveConsumptionReadyV1 = false;
inline constexpr bool kSemanticClosureReadyV1 = false;
inline constexpr bool kProductionAuthorityV1 = false;
inline constexpr bool kWitnessRecursiveConsumptionReadyV2 = false;
inline constexpr bool kWitnessSemanticClosureReadyV2 = false;
inline constexpr bool kWitnessProductionAuthorityV2 = false;
static_assert(!kRecursiveConsumptionReadyV1);
static_assert(!kSemanticClosureReadyV1);
static_assert(!kProductionAuthorityV1);
static_assert(!kWitnessRecursiveConsumptionReadyV2);
static_assert(!kWitnessSemanticClosureReadyV2);
static_assert(!kWitnessProductionAuthorityV2);

} // namespace matmul::v4::rc::fixed_program_semantic_product

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_SEMANTIC_PRODUCT_H
