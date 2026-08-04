// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_TERMINAL_ALG_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_TERMINAL_ALG_H

#include <matmul/matmul_v4_rc_stage3_episode_digest_all_instance.h>
#include <matmul/matmul_v4_rc_stage3_ordinary_recursive_leaf.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::episode_terminal_alg {

namespace aq = air_quotient;
namespace digest = episode_digest_all_instance;
namespace fp = recursive_fixedpoint;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kChildCountV1 = 5;

enum class ChildKindV1 : uint8_t {
    RoundRoots = 1,
    DigestValue = 2,
    HeaderTarget = 3,
    HeaderPublicMemory = 4,
    DigestPow = 5,
};

/**
 * One source-preserving AlgHash proof for a deterministic public terminal
 * relation.  The verifier reconstructs the AIR, witness-independent seed,
 * and public statement from the consensus statement and the two source
 * products.  A legacy SHA-FRI root is never interpreted as an AlgHash root.
 */
struct ChildProofV1 {
    ChildKindV1 kind{};
    RCStage3RelationEndpoint endpoint{};
    uint256 source_statement{};
    uint256 public_fs_seed{};
    fp::AlgAirProof proof;
    uint256 proof_commitment{};
};

struct ProductV1 {
    uint16_t version{kVersionV1};
    uint256 statement_commitment{};
    uint256 digest_product_commitment{};
    uint256 digest_endpoint_binding_root{};
    uint256 header_target_pin_commitment{};
    std::vector<ChildProofV1> children;
    uint256 product_commitment{};

    /** These remain false until a retained parent consumes every child. */
    bool normalized_recursive_consumed{false};
    bool production_authority{false};
};

/** Exact verifier input for one retained ordinary recursive leaf. */
struct RecursiveChildInputV1 {
    ChildKindV1 kind{};
    RCStage3RelationEndpoint endpoint{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    fp::AlgAirProof proof;
    uint256 public_fs_seed{};
    uint256 source_statement{};
};

[[nodiscard]] uint256 CommitProductV1(
    const ProductV1& product);

/**
 * Build additive Alg proofs for the public terminal relations already
 * represented by the digest and header products.  Both source products are
 * executed first; the new proofs are not accepted as replacements for an
 * invalid source product.
 */
[[nodiscard]] bool ProveProductV1(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const digest::ProductV1& digest_product,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    ProductV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyProductV1(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const digest::ProductV1& digest_product,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    const ProductV1& product,
    std::string* why = nullptr);

/** Verify and rebuild the exact five normalized-parent inputs. */
[[nodiscard]] bool BuildRecursiveChildInputsV1(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const digest::ProductV1& digest_product,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    const ProductV1& product,
    std::vector<RecursiveChildInputV1>& out,
    std::string* why = nullptr);

inline constexpr bool kPublicTerminalAlgExecutableV1 = true;
inline constexpr bool kNormalizedRecursiveConsumedV1 = false;
inline constexpr bool kProductionAuthorityV1 = false;
static_assert(kPublicTerminalAlgExecutableV1);
static_assert(!kNormalizedRecursiveConsumedV1);
static_assert(!kProductionAuthorityV1);

} // namespace matmul::v4::rc::episode_terminal_alg

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_TERMINAL_ALG_H
