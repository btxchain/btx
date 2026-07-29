// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_TILETREE_DIGEST_TERMINAL_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_TILETREE_DIGEST_TERMINAL_H

#include <matmul/matmul_v4_rc_stage3_episode_digest_all_instance.h>
#include <matmul/matmul_v4_rc_stage3_episode_relation_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_round_roots.h>

#include <cstdint>
#include <string>

namespace matmul::v4::rc::episode_tiletree_digest_terminal {

namespace digest = episode_digest_all_instance;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kBusIdV1 = 0x16170008U;
inline constexpr uint32_t kProductionRoundsV1 = 8;
inline constexpr uint32_t kRootBytesPerRoundV1 = 32;
inline constexpr uint32_t kProductionLogicalRowsV1 =
    kProductionRoundsV1 * kRootBytesPerRoundV1;

/**
 * Exact endpoint-22 -> endpoint-23 production terminal.
 *
 * The producer receipt is rebuilt from all eight independently verified
 * TileTreeManifest products. The consumer receipt is rebuilt independently
 * from the complete EpisodeDigestSha256d ProductV1 statement. Both base rows
 * are committed before a single joint seed samples two Fp3 LogUp lanes.
 *
 * No values are serialized outside the two quotient proofs. Verification
 * reconstructs both 8x32-byte inventories from their owning products.
 */
struct ProductV1 {
    uint16_t version{kVersionV1};
    uint256 statement_commitment{};
    uint256 tiletree_collection_commitment{};
    uint256 digest_product_commitment{};
    uint32_t round_count{0};
    uint32_t logical_rows{0};
    uint256 public_challenge_seed{};
    RCStage3ProducerBusReceiptV1 producer;
    RCStage3ProducerBusReceiptV1 consumer;
    uint256 product_commitment{};

    /** Evidence labels only; never readiness switches. */
    bool exact_all_round_inventory{false};
    bool proof_owned_terminal_pair{false};
    bool normalized_recursive_consumed{false};
    bool production_authority{false};
    std::string note;
};

[[nodiscard]] uint256 CommitProductV1(const ProductV1& product);

[[nodiscard]] bool ProveProductV1(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const RCStage3EpisodeRoundRootProducerProduct& tiletree_product,
    const digest::ProductV1& digest_product,
    ProductV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyProductV1(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const RCStage3EpisodeRoundRootProducerProduct& tiletree_product,
    const digest::ProductV1& digest_product,
    const ProductV1& product,
    std::string* why = nullptr);

inline constexpr bool kLocalTerminalExecutableV1 = true;
inline constexpr bool kNormalizedRecursiveConsumedV1 = false;
inline constexpr bool kProductionAuthorityV1 = false;
static_assert(kLocalTerminalExecutableV1);
static_assert(!kNormalizedRecursiveConsumedV1);
static_assert(!kProductionAuthorityV1);

} // namespace matmul::v4::rc::episode_tiletree_digest_terminal

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_TILETREE_DIGEST_TERMINAL_H
