// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_SEMANTIC_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_SEMANTIC_PRODUCT_H

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
inline constexpr uint32_t kFamilyCountV1 = 11;
inline constexpr uint32_t kMaxBoundariesPerChildV1 =
    ha::kFixedProgramVerticalSemanticInstances;

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
static_assert(!kRecursiveConsumptionReadyV1);
static_assert(!kSemanticClosureReadyV1);
static_assert(!kProductionAuthorityV1);

} // namespace matmul::v4::rc::fixed_program_semantic_product

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIXED_PROGRAM_SEMANTIC_PRODUCT_H
