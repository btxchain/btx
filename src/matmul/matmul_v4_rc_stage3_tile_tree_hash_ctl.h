// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_TILE_TREE_HASH_CTL_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_TILE_TREE_HASH_CTL_H

#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_stage3_episode_tile_stream.h>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3TileTreeHashCtlVersion = 1;
inline constexpr uint32_t kRCStage3TileTreeHashCtlBusId =
    0x54483231U; // "TH21"
/** Producer-edge tuple constants (namespace + gamma*stage + gamma^2*address +
 * gamma^3*value); mirror the file-local EDGE_NAMESPACE/EDGE_STAGE. */
inline constexpr uint32_t kRCStage3TileTreeCtlEdgeNamespace = 0x54454831U;
inline constexpr uint32_t kRCStage3TileTreeCtlEdgeStage = 20;

/**
 * One proof-owned 32-byte digest edge between two tile-tree SHA256d nodes.
 *
 * The producer Split-RAP child is a witness-boundary vertical SHA AIR. Its
 * 32 epoch-R0 output-byte columns feed a dual-lane LogUp accumulator in that
 * same trace. The consumer is an independent witness-boundary SHA AIR whose
 * four sparse epoch-R0 first-pass input-byte lanes receive the exact left or
 * right child interval. No manifest byte mirror is accepted as CTL VALUE.
 */
struct RCStage3TileTreeHashEdgeCtlProof {
    uint16_t version{kRCStage3TileTreeHashCtlVersion};
    uint32_t round_index{0};
    uint32_t producer_node_ordinal{0};
    uint32_t consumer_node_ordinal{0};
    uint32_t consumer_preimage_offset{0};
    RCStage3RelationEndpoint producer_endpoint{};
    RCStage3RelationEndpoint consumer_endpoint{};
    uint256 statement_commitment{};
    uint256 tree_manifest_commitment{};
    uint256 producer_public_statement{};
    uint256 consumer_public_statement{};
    uint256 producer_r0_root{};
    uint256 consumer_r0_root{};
    RCStage3CtlManifest manifest;
    std::vector<RCStage3CtlChildPin> pins;
    air_quotient::AirQuotientSplitRapRowsProof producer_proof;
    air_quotient::AirQuotientSplitRapRowsProof consumer_proof;
    uint256 producer_proof_commitment{};
    uint256 consumer_proof_commitment{};
    uint256 proof_commitment{};
};

struct RCStage3TileTreeHashCtlProof {
    uint16_t version{kRCStage3TileTreeHashCtlVersion};
    uint256 statement_commitment{};
    uint256 tile_stream_collection_commitment{};
    std::vector<RCStage3TileTreeHashEdgeCtlProof> edges;
    uint256 collection_commitment{};
};

[[nodiscard]] bool ProveRCStage3TileTreeHashCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3TileTreeHashCtlProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3TileTreeHashCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    const RCStage3TileTreeHashCtlProof& proof,
    std::string* why = nullptr);

/**
 * Native producer-edge AirConstraintSystem (gamma/alpha baked as closure
 * constants, gamma-power tuple NS + gamma*stage + gamma^2*byte + gamma^3*value).
 * Exposed so the constraint-bytecode transport-lane migration can be
 * DIFFERENTIALLY tested against the exact native relation. 134 constraints:
 * for each of 32 bytes x 2 lanes an inverse (first-row) and a padding
 * (transition) constraint, then per lane running-first/transition/last. The 32
 * output-byte columns start at `output_byte_base`; the two inverse banks and
 * the two running columns are appended after them. Only constraints are built
 * (no witness), so arbitrary challenges/terminal are accepted.
 */
[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3TileTreeProducerConstraintSystem(
    uint32_t output_byte_base,
    uint32_t n_rows,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal);

} // namespace matmul::v4::rc

#endif
