// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_PROOF_TAPE_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_PROOF_TAPE_JOIN_H

#include <matmul/matmul_v4_rc_stage3_episode_wiring_proof_descriptor.h>
#include <matmul/matmul_v4_rc_stage3_ordinary_recursive_leaf.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_episode_wiring_proof_tape_join {

namespace descriptor =
    stage3_episode_wiring_proof_descriptor;
namespace fixedpoint = recursive_fixedpoint;
namespace gf = gkr_field;
namespace ordinary = stage3_ordinary_recursive_leaf;
namespace aq = air_quotient;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kTerminalLanesV1 =
    descriptor::kTerminalLanesV1;

/**
 * Verifier-rebuilt public identity shared by the descriptor producer, the
 * canonical tape consumer and their equality link.  No value is learned from
 * any child receipt.
 */
struct StatementV1 {
    uint16_t version{kVersionV1};
    uint256 product_commitment{};
    uint256 statement_commitment{};
    uint256 schedule_root{};
    uint256 proof_wire_root{};
    uint32_t record_count{0};
    descriptor::ChallengesV1 challenges{};
    std::array<gf::Fp3, kTerminalLanesV1>
        producer_terminal{};
    std::array<gf::Fp3, kTerminalLanesV1>
        consumer_terminal{};

    bool operator==(const StatementV1& other) const;
};

[[nodiscard]] bool BuildStatementV1(
    const descriptor::ManifestV1& manifest,
    StatementV1& out,
    std::string* why = nullptr);

/**
 * Consumer-side ordinary AIR.  It is intentionally rebuilt by a second call
 * to the canonical manifest/product builders and receives a distinct
 * protocol binding/Fiat--Shamir seed.  This authenticates the exact legacy
 * proof tape as a child; it does not yet arithmetize the legacy FRI verifier.
 */
struct ConsumerV1 {
    descriptor::ManifestV1 manifest{};
    descriptor::ProductV1 product{};
    ordinary::PublicBindingV1 binding{};
    ordinary::ProofV1 ordinary_proof{};
    bool exact_canonical_inventory{false};
    bool independently_rebuilt_air{false};
    bool legacy_fri_verifier_in_air{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ConsumerV1 BuildAndProveConsumerV1(
    const RCStage3EpisodeWiringProduct& wiring);

[[nodiscard]] ConsumerV1 BuildAndProveConsumerManifestV1(
    const descriptor::ManifestV1& manifest);

[[nodiscard]] bool VerifyConsumerV1(
    const RCStage3EpisodeWiringProduct& wiring,
    const ConsumerV1& consumer,
    std::string* why = nullptr);

/** Two-row, dual-Fp3 equality/cancellation AIR. */
struct LinkProductV1 {
    StatementV1 statement{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    ordinary::PublicBindingV1 binding{};
    std::array<gf::Fp3, kTerminalLanesV1>
        cancellation{};
    uint32_t violations{0};
    bool all_roots_bound{false};
    bool receipt_pair_bound{false};
    bool dual_fp3_terminal_cancellation{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] LinkProductV1 BuildLinkProductV1(
    const StatementV1& statement,
    const uint256& producer_receipt_commitment,
    const uint256& consumer_receipt_commitment);

struct ProofV1 {
    uint16_t version{kVersionV1};
    StatementV1 statement{};
    ordinary::ProofV1 producer{};
    ConsumerV1 consumer{};
    ordinary::ProofV1 equality_link{};
    fixedpoint::NarrowRetainedReceiptParentV1 parent{};
    uint256 parent_node_binding{};
    uint256 parent_program_binding{};
    bool three_ordinary_children_verified{false};
    bool normalized_parent_proof_verified{false};
    bool host_composition_authenticated{false};
    bool legacy_fri_verifier_in_parent_air{false};
    bool complete_fixed_point{false};
    bool semantic_sites_credited{false};
    bool authority_ready{false};
    bool construction_valid{false};
    std::string note;
};

/**
 * Produce all three ordinary children and one retained normalized parent.
 * The parent consumes exact receipt commitments in producer/consumer/link
 * order and rejects duplicate proof positions.
 */
[[nodiscard]] ProofV1 ProveV1(
    const RCStage3EpisodeWiringProduct& wiring,
    bool prove_parent = true);

/** Bounded proof-level canary over an already canonical manifest. */
[[nodiscard]] ProofV1 ProveManifestV1(
    const descriptor::ManifestV1& manifest,
    bool prove_parent = true);

/**
 * Independently rebuild every child statement/AIR and the parent fold-bus,
 * then verify the retained parent proof without trusting callback-bearing
 * receipt state.
 */
[[nodiscard]] bool VerifyV1(
    const RCStage3EpisodeWiringProduct& wiring,
    const ProofV1& proof,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyManifestV1(
    const descriptor::ManifestV1& manifest,
    const ProofV1& proof,
    std::string* why = nullptr);

inline constexpr bool kConsumerOrdinaryProofExecutableV1 = true;
inline constexpr bool kSameParentCancellationExecutableV1 = true;
inline constexpr bool kLegacyFriVerifierInParentAirV1 = false;
inline constexpr bool kCompleteFixedPointV1 = false;
inline constexpr bool kSemanticSitesCreditedV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;

static_assert(!kLegacyFriVerifierInParentAirV1);
static_assert(!kCompleteFixedPointV1);
static_assert(!kSemanticSitesCreditedV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_episode_wiring_proof_tape_join

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_PROOF_TAPE_JOIN_H
