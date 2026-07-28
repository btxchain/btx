// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_AUTHORITY_RECEIPT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_AUTHORITY_RECEIPT_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::normalized_authority {

namespace aq = air_quotient;

/** "NAV3" in canonical little-endian wire order. */
inline constexpr uint32_t kReceiptMagicV3 = 0x3356414eU;
inline constexpr uint16_t kReceiptVersionV3 = 3;
inline constexpr uint16_t kFpExtensionDegreeV3 = 3;
inline constexpr uint16_t kFriQueriesV3 =
    static_cast<uint16_t>(kRCFri3AlgNumQueries);
inline constexpr uint16_t kOodCandidatesV3 =
    static_cast<uint16_t>(kRCFri3AlgSafeQ192K2OodCandidatesV13);
inline constexpr uint16_t kSafeBackendVersionV3 =
    static_cast<uint16_t>(kRCFri3AlgMultiRowSafeQ192K2ProofVersionV13);
inline constexpr uint16_t kOuterProofVersionV3 =
    aq::kAirQuotientSplitRapRowsSafeFixedProofVersionV3;
inline constexpr uint16_t kRoleCountV3 =
    kRCStage3RelationClosureRoleCount;
inline constexpr uint16_t kEndpointCountV3 =
    kRCStage3RelationClosureEndpointCount;

/**
 * Public composed-work statement carried by a direct BNV3 receipt.
 *
 * The legacy outer section envelope used to carry these values.  BNV3 carries
 * only the normalized receipt, so omitting them would leave a fresh consensus
 * verifier unable to reconstruct which episode and coupled digests the parent
 * proves.  `transcript_commitment` is deliberately absent: the direct receipt
 * has its own canonical root and must not create a self-reference.
 */
struct ComposedPublicStatementV3 {
    int32_t height{0};
    uint32_t n_bits{0};
    uint32_t episode_profile{0};
    uint32_t coupled_profile{0};
    uint32_t transcript_version{0};
    ProductionProgramConsensusPinV1 program_consensus_pin{};
    uint256 header_commitment{};
    uint256 params_commitment{};
    uint256 target{};
    uint256 sigma{};
    uint256 episode_digest{};
    uint256 coupled_digest{};
    uint256 final_digest{};

    bool operator==(const ComposedPublicStatementV3&) const = default;
};

enum class OuterBindingKindV3 : uint8_t {
    /** Direct BNV3 body: statement plus canonical role pins. */
    DirectBlockReceipt = 1,
    /** Compatibility path for the legacy fifteen-section outer envelope. */
    LegacyCompositionEnvelope = 2,
};

/**
 * One endpoint in the exact canonical 52-endpoint semantic inventory.
 *
 * Every root is proof/public-statement material.  No execution result,
 * readiness bit, callback, cache handle or timing is carried on the wire.
 */
struct EndpointPinV3 {
    RCStage3RelationEndpoint endpoint{};
    uint64_t instance_count{0};
    uint256 manifest_root{};
    uint256 relation_proof_root{};
    uint256 semantic_root{};
    uint256 ctl_terminal_root{};
    uint256 recursive_child_statement_root{};

    bool operator==(const EndpointPinV3&) const = default;
};

/** One canonical role program and its ordered endpoint statements. */
struct RolePinV3 {
    RCStage3RelationRole role{};
    uint256 program_root{};
    uint256 relation_statement_root{};
    std::vector<EndpointPinV3> endpoints;
    uint256 endpoint_manifest_root{};
    uint256 role_statement_root{};

    bool operator==(const RolePinV3&) const = default;
};

/**
 * Public parent shape.  These values are statement inputs, never performance
 * observations. `proof_columns` excludes the quotient column.
 */
struct ParentShapeV3 {
    uint32_t trace_rows{0};
    uint32_t semantic_columns{0};
    uint32_t proof_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint32_t quotient_rows{0};
    uint32_t fri_n_coeffs{0};
    uint32_t lde_rows{0};

    bool operator==(const ParentShapeV3&) const = default;
};

/**
 * Canonical block-sized authority receipt prerequisite.
 *
 * This object is not itself authority.  After it validates, consensus still
 * must reconstruct the exact parent AIR from the pinned registry/program
 * roots and invoke AirQuotientVerifyRowsSplitRapSafeFixedV3.  The receipt
 * deliberately contains no host-provided "verified" or "ready" value.
 */
struct NormalizedAuthorityReceiptV3 {
    uint32_t magic{kReceiptMagicV3};
    uint16_t version{kReceiptVersionV3};
    uint16_t fp_extension_degree{kFpExtensionDegreeV3};
    uint16_t fri_queries{kFriQueriesV3};
    uint16_t ood_candidates{kOodCandidatesV3};
    uint16_t safe_backend_version{kSafeBackendVersionV3};
    uint16_t outer_proof_version{kOuterProofVersionV3};

    OuterBindingKindV3 outer_binding_kind{
        OuterBindingKindV3::DirectBlockReceipt};
    ComposedPublicStatementV3 public_statement{};
    uint256 outer_statement_root{};
    uint256 program_registry_root{};
    uint256 topology_manifest_root{};
    uint256 aggregation_schedule_root{};
    uint256 occurrence_manifest_root{};
    uint256 verifier_program_root{};
    uint256 abi_plan_root{};
    uint256 selection_plan_root{};
    uint256 derived_hash_plan_root{};

    std::vector<uint32_t> fixed_trace_columns;
    uint256 fixed_trace_row_root{};
    uint256 fixed_trace_manifest_root{};

    std::vector<RolePinV3> roles;
    uint256 role_manifest_root{};

    ParentShapeV3 parent_shape{};
    uint256 parent_node_binding{};
    uint256 parent_context_binding{};
    uint256 parent_program_root{};
    uint256 parent_cs_commitment{};
    uint256 parent_statement_root{};
    uint256 parent_fs_seed{};

    std::vector<unsigned char> parent_proof_bytes;
    uint256 parent_proof_root{};
    uint256 receipt_root{};

    bool operator==(const NormalizedAuthorityReceiptV3&) const = default;
};

/**
 * Verifier-rebuilt public inputs.  This type intentionally has no derived
 * roots and no execution booleans: validation recomputes those roots from
 * these exact components and compares them to the receipt.
 */
struct RebuiltVerifierInputsV3 {
    OuterBindingKindV3 outer_binding_kind{
        OuterBindingKindV3::DirectBlockReceipt};
    ComposedPublicStatementV3 public_statement{};
    uint256 outer_statement_root{};
    uint256 program_registry_root{};
    uint256 topology_manifest_root{};
    uint256 aggregation_schedule_root{};
    uint256 occurrence_manifest_root{};
    uint256 verifier_program_root{};
    uint256 abi_plan_root{};
    uint256 selection_plan_root{};
    uint256 derived_hash_plan_root{};

    std::vector<uint32_t> fixed_trace_columns;
    uint256 fixed_trace_row_root{};
    std::vector<RolePinV3> roles;

    ParentShapeV3 parent_shape{};
    uint256 parent_node_binding{};
    uint256 parent_context_binding{};
    uint256 parent_program_root{};
    uint256 parent_cs_commitment{};

    bool operator==(const RebuiltVerifierInputsV3&) const = default;
};

[[nodiscard]] uint256 ComputeEndpointPinRootV3(
    const EndpointPinV3& endpoint);
[[nodiscard]] uint256 ComputeRoleEndpointManifestRootV3(
    const RolePinV3& role);
[[nodiscard]] uint256 ComputeRoleStatementRootV3(
    const RolePinV3& role);
[[nodiscard]] uint256 ComputeRoleManifestRootV3(
    const std::vector<RolePinV3>& roles);
[[nodiscard]] uint256 ComputeDirectOuterStatementRootV3(
    const ComposedPublicStatementV3& statement,
    const std::vector<RolePinV3>& roles);
[[nodiscard]] uint256 ComputeFixedTraceManifestRootV3(
    const ParentShapeV3& shape,
    const std::vector<uint32_t>& ordered_columns,
    const uint256& row_root);
[[nodiscard]] uint256 ComputeParentStatementRootV3(
    const RebuiltVerifierInputsV3& inputs);
[[nodiscard]] uint256 DeriveParentFsSeedV3(
    const uint256& parent_statement_root);
[[nodiscard]] uint256 ComputeParentProofRootV3(
    const std::vector<unsigned char>& proof_bytes);
[[nodiscard]] uint256 ComputeReceiptRootV3(
    const NormalizedAuthorityReceiptV3& receipt);

/**
 * Check canonical inventory, all derived roots and the canonical SAFE
 * FixedTrace V3 proof codec.  It does not execute the parent AIR.
 */
[[nodiscard]] bool ValidateNormalizedAuthorityReceiptV3(
    const NormalizedAuthorityReceiptV3& receipt,
    std::string* why = nullptr);

/**
 * Bind the receipt to verifier-rebuilt inputs and return the decoded root
 * proof and fixed-trace pin needed by the mandatory native verifier call.
 * Missing/null parent-CS commitment or root proof is rejected.
 */
[[nodiscard]] bool ValidateAndDecodeVerifierInputsV3(
    const NormalizedAuthorityReceiptV3& receipt,
    const RebuiltVerifierInputsV3& rebuilt,
    aq::AirQuotientSplitRapRowsProof& decoded_parent_proof,
    aq::AirQuotientFixedTracePinV3& fixed_trace,
    std::string* why = nullptr);

/** Strict bounded canonical little-endian codec. */
[[nodiscard]] size_t SerializeNormalizedAuthorityReceiptV3(
    const NormalizedAuthorityReceiptV3& receipt,
    std::vector<unsigned char>& out);
[[nodiscard]] std::optional<NormalizedAuthorityReceiptV3>
DeserializeNormalizedAuthorityReceiptV3(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::normalized_authority

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_AUTHORITY_RECEIPT_H
