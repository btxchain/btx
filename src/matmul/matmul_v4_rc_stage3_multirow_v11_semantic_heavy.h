// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_HEAVY_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_HEAVY_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_exports.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::multirow_v11_semantic_heavy {

namespace aq = air_quotient;
namespace exports = multirow_v11_semantic_exports;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kHeavyEndpointCountV1 = 21;
inline constexpr uint32_t kRootWordsV1 = 8;

/**
 * The exact proof-owned child route.  The ordinal is the global endpoint
 * ordinal (endpoint id - 1), not a prover-selected position.
 */
struct HeavyRouteV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint32_t ordinal{0};
    RCStage3StreamFamily family{
        RCStage3StreamFamily::CompleteStream};

    bool operator==(const HeavyRouteV1&) const = default;
};

/**
 * One real heavy child proof.
 *
 * The Split-RAP R0 group is the exact proof-owned preprocessed group exported
 * by the canonical SHA/XOF/ChaCha child builder.  Its root is already pinned
 * by `preprocessed_row_group_roots`.  The terminal eight output words remain
 * in the same child AIR, constrained to the terminal fold and to the endpoint
 * root independently pinned by the canonical role AIR. `proof_commitment`
 * commits the complete canonical proof codec, not a host-side success bit.
 */
struct HeavyChildProofV1 {
    uint16_t version{kVersionV1};
    HeavyRouteV1 route;
    RCStage3StreamEndpointManifest manifest;
    std::array<uint32_t, kRootWordsV1> committed_root{};
    std::vector<uint32_t> r0_columns;
    uint256 r0_root{};
    uint256 proof_commitment{};
    aq::AirQuotientSplitRapRowsProof split_rap;
    uint32_t child_rows{0};
    uint32_t child_columns{0};
    uint32_t semantic_compressions{0};
    size_t proof_bytes{0};
    bool quotient_division_exact{false};
    bool native_verifier_accepted{false};
    bool recursively_consumed{false};
    std::string residual;
};

struct HeavyInventoryEntryV1 {
    HeavyRouteV1 route;
    bool role_supplied{false};
    bool child_supplied{false};
    bool role_root_canonical{false};
    bool root_matches_role{false};
    bool split_rap_verified{false};
    uint256 r0_root{};
    size_t proof_bytes{0};
    std::string residual;
};

/**
 * Exact 21-child result.  Partial input remains useful as an honest progress
 * inventory, but `valid` and `complete` stay false until all required roles
 * and all 21 verifying child proofs are present exactly once.
 */
struct ProductV1 {
    uint16_t version{kVersionV1};
    std::vector<HeavyInventoryEntryV1> endpoints;
    std::vector<uint16_t> residual_endpoint_ids;
    uint32_t supplied_roles{0};
    uint32_t required_roles{0};
    uint32_t verified_children{0};
    uint32_t semantic_literal_endpoints{0};
    size_t total_proof_bytes{0};
    bool exact_inventory{false};
    bool no_duplicate_roles{false};
    bool no_duplicate_children{false};
    bool all_required_roles_supplied{false};
    bool all_children_verified{false};
    bool semantic_exports_complete{false};
    bool recursively_consumed{false};
    bool complete{false};
    bool valid{false};
    bool production_authority{false};
    std::string note;
};

/** Exact immutable list: endpoint ids
 * 2,3,12,19-27,29,35,44,47-52. */
[[nodiscard]] std::array<HeavyRouteV1, kHeavyEndpointCountV1>
CanonicalHeavyRoutesV1();

/**
 * Prove one child with the executable Q192 Split-RAP backend.  The supplied
 * role must be the canonical executed role product and must already carry the
 * root produced by `manifest`; otherwise proof construction fails closed.
 */
[[nodiscard]] HeavyChildProofV1 ProveHeavyChildV1(
    const RCStage3RoleAirProduct& role,
    RCStage3RelationEndpoint endpoint,
    const RCStage3StreamEndpointManifest& manifest,
    const uint256& public_fs_seed,
    std::string* why = nullptr);

/**
 * Rebuild the role CS and heavy child CS from canonical constructors, replay
 * the child transcript seed, verify the Q192 proof, and rederive both the R0
 * and codec commitments.
 */
[[nodiscard]] bool VerifyHeavyChildV1(
    const RCStage3RoleAirProduct& role,
    const HeavyChildProofV1& proof,
    const uint256& public_fs_seed,
    std::string* why = nullptr);

[[nodiscard]] ProductV1 BuildProductV1(
    const std::vector<RCStage3RoleAirProduct>& roles,
    const std::vector<HeavyChildProofV1>& children,
    const uint256& public_fs_seed);

[[nodiscard]] bool ValidateProductV1(
    const ProductV1& product,
    const std::vector<RCStage3RoleAirProduct>& roles,
    const std::vector<HeavyChildProofV1>& children,
    const uint256& public_fs_seed,
    std::string* why = nullptr);

inline constexpr bool kRecursiveConsumptionReadyV1 = false;
inline constexpr bool kProductionAuthorityV1 = false;
static_assert(!kRecursiveConsumptionReadyV1);
static_assert(!kProductionAuthorityV1);

} // namespace matmul::v4::rc::multirow_v11_semantic_heavy

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_HEAVY_H
