// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PRODUCTION_PARENT_BUILDER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PRODUCTION_PARENT_BUILDER_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_stage3_normalized_relation_receipt_consumer.h>

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

} // namespace matmul::v4::rc::normalized_production_parent_builder

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PRODUCTION_PARENT_BUILDER_H
