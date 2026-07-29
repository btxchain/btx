// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ENDPOINT_RECEIPT_INTAKE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ENDPOINT_RECEIPT_INTAKE_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_exports.h>
#include <matmul/matmul_v4_rc_stage3_ordinary_recursive_leaf.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_semantic_endpoint_receipt_intake {

namespace exports = multirow_v11_semantic_exports;
namespace fixedpoint = recursive_fixedpoint;
namespace gf = gkr_field;
namespace ordinary = stage3_ordinary_recursive_leaf;
namespace aq = air_quotient;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kEndpointCountV1 =
    exports::kEndpointCountV1;
inline constexpr uint32_t kRootWordsV1 =
    exports::kRootWordsV1;
inline constexpr uint32_t kTerminalLanesV1 = 2;
inline constexpr uint32_t kNoReceiptSlotV1 = UINT32_MAX;
inline constexpr uint64_t kEndpointMaskV1 =
    (uint64_t{1} << kEndpointCountV1) - 1U;

struct ChallengesV1 {
    std::array<gf::Fp3, kTerminalLanesV1> gamma{};
    std::array<gf::Fp3, kTerminalLanesV1> alpha{};

    bool operator==(const ChallengesV1& other) const
    {
        for (uint32_t lane = 0;
             lane < kTerminalLanesV1; ++lane) {
            if (!gf::Eq(gamma[lane], other.gamma[lane]) ||
                !gf::Eq(alpha[lane], other.alpha[lane])) {
                return false;
            }
        }
        return true;
    }
};

/**
 * One entry in the verifier-owned canonical 52-endpoint inventory.
 *
 * `present` is true only when a supplied RoleExportProofV1 validates and its
 * exact export is backed by the role witness, any required stream child, the
 * same-trace root equality and canonical u32 limbs.  Route-table literals do
 * not count without that concrete receipt.
 */
struct EndpointEntryV1 {
    exports::CanonicalExportRouteV1 route{};
    std::array<uint32_t, kRootWordsV1> root_words{};
    uint32_t receipt_slot{kNoReceiptSlotV1};
    bool present{false};
    std::string residual;
};

struct ManifestV1 {
    uint16_t version{kVersionV1};
    std::array<EndpointEntryV1, kEndpointCountV1> endpoints{};
    uint64_t active_bitmap{0};
    uint64_t residual_bitmap{kEndpointMaskV1};
    uint32_t active_endpoints{0};
    uint32_t residual_endpoints{kEndpointCountV1};
    uint32_t active_roles{0};
    uint256 inventory_commitment{};
    ChallengesV1 challenges{};
    bool exact_canonical_order{false};
    bool no_duplicate_roles{false};
    bool no_duplicate_stream_children{false};
    bool all_supplied_role_proofs_valid{false};
    bool complete_52{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildManifestV1(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    ManifestV1& out,
    std::string* why = nullptr);

struct RoleReceiptV1 {
    RCStage3RelationRole role{};
    std::vector<uint32_t> endpoint_ordinals;
    std::array<gf::Fp3, kTerminalLanesV1> terminal{};
    std::array<uint32_t, kTerminalLanesV1> terminal_columns{};
    ordinary::PublicBindingV1 binding{};
    ordinary::ProofV1 ordinary_proof{};
    bool exact_endpoint_order{false};
    bool proof_owned_terminal{false};
    /** Native callback AIR today; canonical bytecode migration is residual. */
    bool canonical_terminal_constraint_bytecode{false};
    bool valid{false};
    std::string note;
};

struct LinkReceiptV1 {
    std::array<gf::Fp3, kTerminalLanesV1> source_terminal{};
    std::array<gf::Fp3, kTerminalLanesV1> consumer_terminal{};
    std::array<uint32_t, kTerminalLanesV1>
        source_terminal_columns{{0, 1}};
    std::array<uint32_t, kTerminalLanesV1>
        consumer_terminal_columns{{2, 3}};
    ordinary::PublicBindingV1 binding{};
    ordinary::ProofV1 ordinary_proof{};
    bool ordered_receipts_bound{false};
    bool dual_fp3_terminal_cancellation{false};
    bool valid{false};
    std::string note;
};

struct ProofV1 {
    uint16_t version{kVersionV1};
    ManifestV1 manifest{};
    std::vector<RoleReceiptV1> role_receipts;
    LinkReceiptV1 equality_link{};
    /** Exact parent child order: all canonical-role receipts, then link. */
    std::vector<uint256> ordered_child_receipt_commitments;
    fixedpoint::NarrowRetainedReceiptParentV1 parent{};
    uint256 parent_node_binding{};
    uint256 parent_program_binding{};
    bool exact_no_omission_no_duplicate_intake{false};
    bool all_ordinary_receipts_verified{false};
    bool canonical_terminal_constraint_bytecode_complete{false};
    bool normalized_parent_proof_verified{false};
    bool recursive_child_verifier_constraints_complete{false};
    bool semantic_sites_credited{false};
    bool complete_fixed_point{false};
    bool authority_ready{false};
    bool construction_valid{false};
    std::string note;
};

/**
 * Build concrete role receipts, the equality-link receipt and their retained
 * same-parent join.  `prove_parent=false` is a bounded construction canary;
 * VerifyV1 intentionally requires the real parent proof.
 */
[[nodiscard]] ProofV1 ProveV1(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    bool prove_parent = true);

/**
 * Verify the complete proof-owned intake up through the ordinary equality
 * link.  This is useful for bounded attack tests and never claims recursive
 * consumption.
 */
[[nodiscard]] bool VerifyIntakeV1(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    const ProofV1& proof,
    std::string* why = nullptr);

/** VerifyIntakeV1 plus the retained normalized parent proof. */
[[nodiscard]] bool VerifyV1(
    const std::vector<RCStage3RoleAirProduct>& role_artifacts,
    const std::vector<exports::StreamChildArtifactV1>&
        stream_children,
    const ProofV1& proof,
    std::string* why = nullptr);

inline constexpr bool kConcreteReceiptIntakeExecutableV1 = true;
inline constexpr bool kRecursiveChildVerifierConstraintsCompleteV1 = false;
inline constexpr bool kSemanticSitesCreditedV1 = false;
inline constexpr bool kCompleteFixedPointV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;

static_assert(!kRecursiveChildVerifierConstraintsCompleteV1);
static_assert(!kSemanticSitesCreditedV1);
static_assert(!kCompleteFixedPointV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_semantic_endpoint_receipt_intake

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ENDPOINT_RECEIPT_INTAKE_H
