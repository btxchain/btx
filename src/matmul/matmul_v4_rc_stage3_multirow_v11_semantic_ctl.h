// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_CTL_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_CTL_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::multirow_v11_semantic_ctl {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kProgramFamiliesV1 = 28;
inline constexpr uint32_t kEndpointFamiliesV1 = 52;
inline constexpr uint32_t kRolesV1 = 14;
inline constexpr uint32_t kDigestWordsV1 = 8;
inline constexpr uint32_t kValueWordsV1 = 8;
inline constexpr uint32_t kBitsPerValueWordV1 = 32;
inline constexpr uint32_t kNoFamilyV1 = UINT32_MAX;

/**
 * One verifier-ordered endpoint value pair.
 *
 * The source words are intended to be direct aliases of the owning role
 * proof's exported cells. `BuildProductV1` independently recomputes whether
 * that alias exists; no caller-supplied ownership boolean is trusted.
 * `consumer_words` are the exact endpoint consumer cells. Both arrays use raw
 * u64 storage so non-canonical x+p and >u32 encodings are rejected before
 * conversion to Fp3 can erase them.
 */
struct EndpointCellsV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint32_t occurrence{0};
    std::array<uint64_t, kValueWordsV1> source_words{};
    std::array<uint64_t, kValueWordsV1> consumer_words{};

    bool operator==(const EndpointCellsV1&) const = default;
};

enum EndpointResidualV1 : uint32_t {
    ResidualNoSelectedProgramV1 = 1U << 0,
    ResidualNoCanonicalOutputV1 = 1U << 1,
    ResidualNoRelationAirCellV1 = 1U << 2,
    ResidualNoSameTraceCtlAliasV1 = 1U << 3,
    ResidualNoRecursiveChildAcceptanceV1 = 1U << 4,
    ResidualNoRecursiveCtlConsumptionV1 = 1U << 5,
};

struct EndpointCoverageV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint32_t occurrence{0};
    uint32_t family_index{kNoFamilyV1};
    uint32_t relation_column{UINT32_MAX};
    bool represented{false};
    bool exact_consumer{false};
    bool selected_program{false};
    bool literal_proof_owned_export{false};
    bool dual_logup_constrained{false};
    bool recursively_consumed{false};
    uint32_t residual_mask{0};
    std::string residual;

    bool operator==(const EndpointCoverageV1&) const = default;
};

struct RoleCoverageV1 {
    RCStage3RelationRole role{};
    uint32_t required_endpoints{0};
    uint32_t represented_endpoints{0};
    uint32_t proof_owned_exports{0};
    uint32_t recursively_consumed_endpoints{0};
    uint64_t endpoint_mask{0};
    uint64_t proof_owned_mask{0};
    bool complete{false};

    bool operator==(const RoleCoverageV1&) const = default;
};

/**
 * Constant-width event layout. Each semantic endpoint occupies exactly two
 * rows: a +1 role-export row and a -1 endpoint-consumer row. `polarity` is
 * deliberately excluded from tuple compression; `direction` is the logical
 * export-to-consumer direction and is included in both matching tuples.
 *
 * Every tag except VALUE is verifier-owned preprocessing. VALUE is eight
 * canonical u32 limbs, with 32 boolean decomposition columns per limb.
 */
struct LayoutV1 {
    uint32_t active{0};
    uint32_t polarity{0};
    uint32_t role{0};
    uint32_t endpoint{0};
    uint32_t direction{0};
    uint32_t occurrence{0};
    uint32_t temporal_order{0};
    uint32_t family_index{0};
    uint32_t site_kind{0};
    uint32_t ownership_bits{0};
    uint32_t program_external_base{0};
    uint32_t program_recursive_base{0};
    uint32_t ali_compiled_program_base{0};
    uint32_t statement_root_base{0};
    uint32_t value_base{0};
    uint32_t value_bits_base{0};
    uint32_t inverse1{0};
    uint32_t inverse2{0};
    uint32_t term1{0};
    uint32_t term2{0};
    uint32_t running1{0};
    uint32_t running2{0};
    uint32_t total_columns{0};
};

struct ProductV1 {
    uint16_t version{kVersionV1};
    uint256 expected_statement_root{};
    uint256 production_site_manifest_commitment{};
    uint256 semantic_program_bridge_commitment{};
    uint256 production_ali_manifest_binding{};
    uint256 source_tuple_commitment{};
    uint256 consumer_tuple_commitment{};
    uint256 challenge_commitment{};
    RCStage3CtlChallenges challenges{};

    LayoutV1 layout;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<EndpointCellsV1> endpoint_cells;
    std::vector<EndpointCoverageV1> endpoints;
    std::vector<RoleCoverageV1> roles;

    uint32_t canonical_program_families{0};
    uint32_t represented_endpoints{0};
    uint32_t exact_consumer_endpoints{0};
    uint32_t selected_program_endpoints{0};
    uint32_t proof_owned_export_endpoints{0};
    uint32_t dual_logup_endpoint_pairs{0};
    uint32_t recursively_consumed_endpoints{0};
    uint32_t represented_roles{0};
    uint32_t complete_roles{0};
    uint32_t violations{UINT32_MAX};

    bool canonical_program_inventory{false};
    bool canonical_ali_inventory{false};
    bool exact_endpoint_order{false};
    bool exact_role_order{false};
    bool canonical_u32_values{false};
    bool commitments_before_challenges{false};
    bool independent_domain_separated_lanes{false};
    bool all_endpoint_pairs_algebraically_constrained{false};
    /** False until the V11 split-RAP parent opens these exact committed rows
     * before deriving the two LogUp lanes. */
    bool tuple_commitments_recursively_bound{false};
    bool all_sources_proof_owned{false};
    bool recursive_consumption_complete{false};
    bool production_authority{false};
    bool valid_foundation{false};
    std::string note;
};

/** Canonical endpoint/role/order fixture with deterministic distinct values. */
[[nodiscard]] std::vector<EndpointCellsV1>
BuildDeterministicEndpointCellsV1(uint32_t salt = 1);

/**
 * Build the complete 52-pair dual-Fp3 rational-identity AIR. Challenges are
 * rejection-sampled only after source and consumer tuple commitments exist.
 * The expected statement root is a verifier public input.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const uint256& expected_statement_root,
    const std::vector<EndpointCellsV1>& endpoint_cells);

/**
 * Canonical regeneration plus AIR evaluation. This is a native construction
 * audit, not recursive proof consumption.
 */
[[nodiscard]] bool ValidateProductV1(
    const ProductV1& product,
    const uint256& expected_statement_root,
    std::string* why = nullptr);

[[nodiscard]] uint32_t CountAirViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

inline constexpr bool kRecursiveConsumptionReadyV1 = false;
inline constexpr bool kProductionAuthorityV1 = false;
static_assert(!kRecursiveConsumptionReadyV1);
static_assert(!kProductionAuthorityV1);

} // namespace matmul::v4::rc::multirow_v11_semantic_ctl

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_SEMANTIC_CTL_H
