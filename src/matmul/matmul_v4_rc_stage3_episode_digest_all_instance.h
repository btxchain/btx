// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_DIGEST_ALL_INSTANCE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_DIGEST_ALL_INSTANCE_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_aggregation_schedule.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_root_chain.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::episode_digest_all_instance {

namespace aq = air_quotient;
namespace fp = recursive_fixedpoint;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace scheduler = aggregation_scheduler;
namespace sites = soundness_scenarios;
namespace tape = stage3_multirow_v13_proof_tape_air;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kBoundariesPerProofSiteV1 =
    sites::kProductionPrivateShaSourcesPerProofSiteV1;

/**
 * The already-verified SAFE proof-tape statement which owns the V3 public
 * challenge namespace. This family never accepts a caller-selected challenge:
 * DeriveShardPublicSourceChallengesV3 rebuilds both Fp3 lanes from this exact
 * tuple before any digest-family trace commitment is made.
 */
struct TapeChallengeContextV1 {
    tape::PublicShapeV1 shape;
    tape::PublicBindingV1 binding;
    uint256 source_inventory_root{};
    uint32_t shard_count{0};

    bool operator==(const TapeChallengeContextV1&) const = default;
};

/**
 * One canonical production proof-site. The proof bytes encode an ordinary
 * AlgAir proof, so the exact proof can be passed to the retained narrow
 * recursive verifier without a Split-RAP adapter.
 */
struct SiteReceiptV1 {
    uint32_t site_ordinal{0};
    uint64_t global_leaf_site{0};
    uint32_t boundary_begin{0};
    uint32_t boundary_count{0};
    uint256 boundary_statement{};
    uint256 site_statement_root{};
    uint256 public_fs_seed{};
    uint256 proof_commitment{};
    uint256 proof_wire_root{};
    std::vector<unsigned char> proof_bytes;

    bool operator==(const SiteReceiptV1&) const = default;
};

/**
 * Complete local EpisodeDigestSha256d family product.
 *
 * `manifest` is the typed, ordered relation statement:
 *   SHA256d(kRCEpisodeTag || round_roots).
 * The verifier reconstructs every SHA compression boundary, the immutable
 * global proof-site manifest and the exact family leaf range. No site count,
 * offset, boundary or root is accepted from the prover without recomputation.
 *
 * This closes this selected local family only. Upstream tile-stream
 * provenance and the eventual normalized parent remain separate obligations.
 */
struct ProductV1 {
    uint16_t version{kVersionV1};
    ha::EpisodeDigestManifest manifest;
    uint256 statement_commitment{};
    uint256 production_site_manifest_commitment{};
    uint256 aggregation_schedule_commitment{};
    uint32_t family_index{0};
    uint64_t first_leaf_site{0};
    uint64_t leaf_site_count{0};
    uint32_t boundary_count{0};
    uint256 program_root{};
    uint256 exact_boundary_schedule_root{};
    uint256 proof_owned_output_root{};
    uint256 terminal_digest{};
    uint256 terminal_word_root{};
    /**
     * Existing executed endpoint-23/24 root chain. This links the same
     * verifier-rebuilt compression boundaries to EpisodeDigestValue and the
     * public episode_digest; it is not a boolean stand-in.
     */
    RCStage3EpisodeDigestRootChainProof endpoint_root_chain;
    uint256 endpoint_binding_root{};
    uint256 exact_site_root{};
    std::vector<SiteReceiptV1> sites;
    uint256 product_commitment{};

    /** Informational, recomputed outputs; never readiness switches. */
    bool exact_production_family_coverage{false};
    bool every_site_proof_verified{false};
    bool endpoint_root_chain_verified{false};
    bool ordinary_recursive_leaf_compatible{false};
    bool normalized_recursive_consumed{false};
    bool production_authority{false};
    std::string note;
};

/** Exact verifier input for one retained narrow-recursion child. */
struct RecursiveChildInputV1 {
    aq::AirConstraintSystem<gf::Fp3> cs;
    fp::AlgAirProof proof;
    uint256 public_fs_seed{};
    uint256 site_statement_root{};
    uint64_t global_leaf_site{0};
};

[[nodiscard]] uint256 CommitProductV1(const ProductV1& product);

/** Canonical attachment binding for one serialized ordinary AlgAir proof. */
[[nodiscard]] uint256 CommitProofWireV1(
    const std::vector<unsigned char>& proof_bytes);

[[nodiscard]] bool ProveProductV1(
    const RCStage3SuccinctProof& statement,
    const ha::EpisodeDigestManifest& manifest,
    const TapeChallengeContextV1& tape_context,
    ProductV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyProductV1(
    const RCStage3SuccinctProof& statement,
    const TapeChallengeContextV1& tape_context,
    const ProductV1& product,
    std::string* why = nullptr);

/**
 * Verify the complete product, decode every canonical AlgAir proof, rebuild
 * its proof-independent CS and return the exact narrow-recursion inputs.
 */
[[nodiscard]] bool BuildRecursiveChildInputsV1(
    const RCStage3SuccinctProof& statement,
    const TapeChallengeContextV1& tape_context,
    const ProductV1& product,
    std::vector<RecursiveChildInputV1>& out,
    std::string* why = nullptr);

inline constexpr bool kLocalFamilyExecutableV1 = true;
inline constexpr bool kOrdinaryRecursiveLeafCompatibleV1 = true;
inline constexpr bool kNormalizedRecursiveConsumedV1 = false;
inline constexpr bool kProductionAuthorityV1 = false;
static_assert(kLocalFamilyExecutableV1);
static_assert(kOrdinaryRecursiveLeafCompatibleV1);
static_assert(!kNormalizedRecursiveConsumedV1);
static_assert(!kProductionAuthorityV1);

} // namespace matmul::v4::rc::episode_digest_all_instance

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_DIGEST_ALL_INSTANCE_H
