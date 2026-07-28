// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PRODUCTION_PARENT_BUILDER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PRODUCTION_PARENT_BUILDER_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_stage3_air_parent_composer.h>
#include <matmul/matmul_v4_rc_stage3_normalized_relation_receipt_consumer.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

class CBlock;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc::normalized_production_parent_builder {

namespace consumer = normalized_relation_receipt_consumer;

inline constexpr uint16_t kProductionParentBuildInputVersionV1 = 1;

/**
 * Typed, immutable production build request.
 *
 * There is deliberately no callback, readiness flag, host verification bit or
 * serialized proof in this request.  The only optional value is the exact
 * episode transcript already computed by the solver; omitting it asks the
 * eventual builder to recompute that witness from the finalized header.
 */
struct ProductionParentBuildInputV1 {
    uint16_t version{kProductionParentBuildInputVersionV1};
    const CBlock* solved_block{nullptr};
    const Consensus::Params* params{nullptr};
    int32_t height{-1};
    uint256 target{};
    const std::vector<RCRoundTranscript>* episode_rounds{nullptr};
};

/**
 * One literal endpoint cell in the block-derived fourteen-role parent.
 *
 * `parent_value_column` is the exact ordinary parent column occupied by the
 * role product's endpoint cell.  `root_word_columns` are eight ordinary u32
 * columns (lo32/hi32 for each of the four Goldilocks digest limbs) pinned by
 * the parent AIR to `committed_root`.  This is the canonical 52-endpoint bank;
 * no receipt-carried value or host acceptance bit substitutes for these
 * columns.
 */
struct ProductionEndpointPlacementV1 {
    RCStage3RelationRole role{};
    RCStage3RelationEndpoint endpoint{};
    uint32_t role_ordinal{0};
    uint32_t endpoint_ordinal{0};
    uint32_t parent_value_column{0};
    uint32_t bank_value_column{0};
    std::array<uint32_t, 8> root_word_columns{};
    alg_hash::Digest committed_root{};
    bool literal_value_alias{false};
};

struct ProductionRolePlacementV1 {
    RCStage3RelationRole role{};
    stage3_air_parent_composer::ChildAttachmentV1 attachment;
    std::vector<ProductionEndpointPlacementV1> endpoints;
};

/**
 * Executable local-relation candidate built from the solved block.
 *
 * `local_parent_valid` means the exact fourteen role AIRs, their real
 * block-derived witnesses, and all 52 literal endpoint aliases form one
 * satisfying parent.  It deliberately does not imply production authority:
 * `recursive_semantic_closure_complete` is computed from the live semantic
 * audit and stays false while a role defers a required child proof.
 */
struct ProductionRelationParentCandidateV1 {
    uint16_t version{kProductionParentBuildInputVersionV1};
    air_quotient::AirConstraintSystem<gkr_field::Fp3> cs;
    std::vector<std::vector<gkr_field::Fp3>> columns;
    std::vector<ProductionRolePlacementV1> roles;
    uint256 episode_digest{};
    uint256 coupled_digest{};
    uint256 composed_digest{};
    uint32_t endpoint_count{0};
    uint64_t witness_violations{UINT64_MAX};
    bool exact_role_order{false};
    bool exact_endpoint_order{false};
    bool all_endpoint_cells_literal{false};
    bool local_parent_valid{false};
    bool recursive_semantic_closure_complete{false};
    bool production_authority{false};
    std::vector<std::string> residuals;
    std::string note;
};

enum class ProductionParentBuildStatusV1 : uint8_t {
    NotRequired = 0,
    InvalidRequest = 1,
    UnsupportedStatement = 2,
    ProgramRegistryUnavailable = 3,
    CompleteRelationParentUnavailable = 4,
    Built = 5,
};

[[nodiscard]] const char* ProductionParentBuildStatusNameV1(
    ProductionParentBuildStatusV1 status);

/**
 * Build the canonical episode+coupled relation parent for one solved block.
 *
 * The downstream type is already executable: once this function returns
 * Built, BuildReceiptV1 proves, serializes, decodes and verifies the exact
 * product.  Current code intentionally stops at
 * CompleteRelationParentUnavailable because the in-flight V13/V14/ABI parent
 * is not yet the complete fourteen-role product and no block-to-product
 * witness assembler exists.  This precise status replaces the old untyped
 * "normalized receipt builder unavailable" dead end.
 */
[[nodiscard]] ProductionParentBuildStatusV1
BuildForSolvedBlockV1(
    const ProductionParentBuildInputV1& input,
    consumer::CanonicalRelationParentProductV1& out,
    std::string* why = nullptr);

/**
 * Build and audit the real block-derived fourteen-role parent candidate.
 *
 * This function is useful before authority closes: unlike BuildForSolvedBlockV1
 * it returns the executable local parent even when semantic child consumption
 * is incomplete.  Its status fields are derived from the actual products and
 * live role audit; callers must never treat `local_parent_valid` as authority.
 */
[[nodiscard]] bool BuildRelationParentCandidateForSolvedBlockV1(
    const ProductionParentBuildInputV1& input,
    ProductionRelationParentCandidateV1& out,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::normalized_production_parent_builder

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PRODUCTION_PARENT_BUILDER_H
