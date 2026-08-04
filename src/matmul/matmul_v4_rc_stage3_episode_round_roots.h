// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_ROUND_ROOTS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_ROUND_ROOTS_H

#include <matmul/matmul_v4_rc_stage3_root_chain.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3EpisodeRoundRootProductVersion = 1;

/**
 * One verifier-ordered round-root producer.
 *
 * `tree_manifest.root` is not accepted as a bare manifest field. Verification
 * executes the complete fixed-program SHA provenance bundle for every leaf
 * and internal node and authenticates the canonical boundary word stream with
 * the episode semantic-memory proof.
 */
struct RCStage3EpisodeRoundTileTreeProducer {
    uint32_t round_index{0};
    stage3_hash_air::TileTreeManifest tree_manifest;
    stage3_hash_semantic::FlatBoundaryProofBundle hash_bundle;
    RCStage3EpisodeHashSemanticBinding hash_binding;
};

/**
 * Exact product for endpoint 23 (EpisodeDigestRoundRoots).
 *
 * The round schedule is the verifier-supplied `expected_rounds`; entries are
 * consecutive and omission/duplication/reordering reject. The collection
 * commitment binds only the ordered producer identities. It is not a
 * substitute for executing the child hash proofs.
 */
struct RCStage3EpisodeRoundRootProducerProduct {
    uint16_t version{kRCStage3EpisodeRoundRootProductVersion};
    uint256 statement_commitment{};
    uint32_t expected_rounds{0};
    uint256 digest_manifest_commitment{};
    std::vector<RCStage3EpisodeRoundTileTreeProducer> rounds;
    uint256 collection_commitment{};
};

inline constexpr uint16_t
    kRCStage3EpisodeRoundRootDigestCtlVersion = 1;
inline constexpr uint32_t
    kRCStage3EpisodeRoundRootDigestCtlBusId = 0x17181800U;
inline constexpr uint32_t
    kRCStage3EpisodeTileTreeRootVectorCtlBusId = 0x16170000U;

enum RCStage3EpisodeDigestPreimageByteBridgeColumn : uint32_t {
    kRCStage3EpisodeDigestBridgeActive = 0,
    kRCStage3EpisodeDigestBridgeAddress,
    kRCStage3EpisodeDigestBridgeExpected,
    kRCStage3EpisodeDigestBridgeValue,
    kRCStage3EpisodeDigestBridgeExport,
    kRCStage3EpisodeDigestBridgeBitBase,
    kRCStage3EpisodeDigestBridgeColumns =
        kRCStage3EpisodeDigestBridgeBitBase + 8,
};

struct RCStage3EpisodeRoundRootDigestCtlPin {
    uint16_t version{
        kRCStage3EpisodeRoundRootDigestCtlVersion};
    uint256 statement_commitment{};
    uint256 digest_manifest_commitment{};
    uint256 producer_collection_commitment{};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint64_t address_begin{0};
    uint256 value_root{};
    uint256 program_commitment{};
    uint256 pin_commitment{};

    bool operator==(
        const RCStage3EpisodeRoundRootDigestCtlPin&) const =
        default;
};

/**
 * Executable endpoint-23 -> endpoint-24 byte seam.
 *
 * The producer product re-executes endpoint 23's canonical vector
 * ProgramTable and directly aliases VALUE to its CTL child.  The consumer
 * product executes the byte-range/reconstruction ProgramTable above and
 * aliases EXPORT to the opposing CTL child.  The expected consumer bytes are
 * exactly the root-byte portion of the typed episode-digest preimage.
 */
struct RCStage3EpisodeRoundRootDigestCtlProof {
    uint16_t version{
        kRCStage3EpisodeRoundRootDigestCtlVersion};
    RCStage3EpisodeRoundRootDigestCtlPin bridge_pin;
    RCStage3CtlManifest manifest;
    RCStage3CtlSchedule producer_schedule;
    RCStage3CtlSchedule consumer_schedule;
    std::vector<RCStage3CtlChildPin> pins;
    air_quotient::AirQuotientProof<gkr_field::Fp3>
        producer_product;
    air_quotient::AirQuotientProof<gkr_field::Fp3>
        consumer_product;
    uint256 producer_product_commitment{};
    uint256 consumer_product_commitment{};
    uint256 proof_commitment{};
};

/** Typed endpoint-22 root-byte relation feeding endpoint 23's proof-owned
 * round-root vector. BYTE is the unsigned source cell of the canonical
 * tile-tree signed-byte ProgramTable; the consumer is the root-vector VALUE
 * cell. The complete tile-tree hash product is executed before this seam.
 */
struct RCStage3EpisodeTileTreeRootVectorCtlProof {
    uint16_t version{
        kRCStage3EpisodeRoundRootDigestCtlVersion};
    RCStage3EpisodeRoundRootDigestCtlPin bridge_pin;
    RCStage3CtlManifest manifest;
    RCStage3CtlSchedule producer_schedule;
    RCStage3CtlSchedule consumer_schedule;
    std::vector<RCStage3CtlChildPin> pins;
    air_quotient::AirQuotientProof<gkr_field::Fp3>
        producer_product;
    air_quotient::AirQuotientProof<gkr_field::Fp3>
        consumer_product;
    uint256 producer_product_commitment{};
    uint256 consumer_product_commitment{};
    uint256 proof_commitment{};
};

[[nodiscard]] bool
BuildRCStage3EpisodeDigestPreimageByteBridgeConstraintSystem(
    const RCStage3EpisodeRoundRootDigestCtlPin& pin,
    const std::vector<uint8_t>& root_bytes,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

[[nodiscard]] bool ProveRCStage3EpisodeRoundRootDigestCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    RCStage3EpisodeRoundRootDigestCtlProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeRoundRootDigestCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    const RCStage3EpisodeRoundRootDigestCtlProof& proof,
    std::string* why = nullptr);

[[nodiscard]] bool ProveRCStage3EpisodeTileTreeRootVectorCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    RCStage3EpisodeTileTreeRootVectorCtlProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeTileTreeRootVectorCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    const RCStage3EpisodeTileTreeRootVectorCtlProof& proof,
    std::string* why = nullptr);

[[nodiscard]] uint256
ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
    const RCStage3EpisodeRoundRootProducerProduct& product);

/** Honest all-round tile-tree prover joined to an existing digest root chain. */
[[nodiscard]] bool ProveRCStage3EpisodeRoundRootProducerProduct(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const std::vector<stage3_hash_air::TileTreeManifest>& trees,
    RCStage3EpisodeRoundRootProducerProduct& out,
    std::string* why = nullptr);

/**
 * Validate the immutable round schedule and the exact bytewise root aliases.
 * This routine is structural and deliberately does not claim hash execution.
 */
[[nodiscard]] bool ValidateRCStage3EpisodeRoundRootProducerSchedule(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const stage3_hash_air::EpisodeDigestManifest& digest_manifest,
    const RCStage3EpisodeRoundRootProducerProduct& product,
    std::string* why = nullptr);

/**
 * Execute all per-round tile-tree hash proofs, then consume their roots in the
 * existing proof-owned EpisodeDigestRoundRoots vector. No native tile-tree or
 * SHA replay is accepted.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeRoundRootProducerProduct(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const stage3_hash_air::EpisodeDigestManifest& digest_manifest,
    const RCStage3RootChainVectorPin& round_roots_pin,
    const RCStage3RootChainVectorProof& round_roots_proof,
    const RCStage3EpisodeRoundRootProducerProduct& product,
    std::string* why = nullptr);

/**
 * Fail-closed combined seam. Callers cannot verify the episode digest chain
 * while forgetting the round-root producer product.
 */
[[nodiscard]] bool
VerifyRCStage3EpisodeDigestRootChainWithRoundRootProducers(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& root_chain,
    const RCStage3EpisodeRoundRootProducerProduct& producers,
    std::string* why = nullptr);

struct RCStage3EpisodeRoundRootProducerAudit {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeDigestRoundRoots};
    bool verifier_ordered_round_schedule{false};
    bool all_tile_tree_hash_children_executed{false};
    bool tile_root_to_digest_vector_equality{false};
    /** Direct endpoint-22 -> endpoint-23 producer edge. */
    bool immediate_producer_link_executable{false};
    bool proof_owned_digest_vector_executed{false};
    bool tile_root_to_round_vector_ctl_executable{false};
    /** Endpoint-23 VALUE and endpoint-24 typed preimage bytes are opposing
     * participants in one exact-row, same-trace dual-LogUp product. */
    bool round_root_to_digest_preimage_ctl_executable{false};
    bool downstream_digest_chain_composable{false};
    bool local_relation_complete{false};
    bool upstream_tile_stream_equality{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3EpisodeRoundRootProducerAudit
CurrentRCStage3EpisodeRoundRootProducerAudit();

inline constexpr bool
    kRCStage3EpisodeRoundRootProducerLocalRelationExecutable = true;
inline constexpr bool
    kRCStage3EpisodeRoundRootProducerTransitivelyComplete = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_ROUND_ROOTS_H
