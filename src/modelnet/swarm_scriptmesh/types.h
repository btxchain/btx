// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCRIPTMESH_TYPES_H
#define BITCOIN_MODELNET_SWARM_SCRIPTMESH_TYPES_H

#include <cstdint>
#include <vector>

namespace modelnet {

/** SHA-256 claim hash length. Any other size is PREIMAGE. */
inline constexpr std::size_t kSwarmScriptMeshHashSize = 32;

/**
 * Minimum block-height rise from the previous stored hop.
 * A smaller rise is TIMEOUT and is not stored.
 */
inline constexpr int64_t kSwarmScriptMeshExpiryRise = 160;

inline constexpr char kSwarmScriptMeshPreimage[] = "PREIMAGE";
inline constexpr char kSwarmScriptMeshKey[] = "KEY";
inline constexpr char kSwarmScriptMeshTimeout[] = "TIMEOUT";
inline constexpr char kSwarmScriptMeshHops[] = "HOPS";
inline constexpr char kSwarmScriptMeshScript[] = "SCRIPT";
inline constexpr char kSwarmScriptMeshReplay[] = "REPLAY";
inline constexpr char kSwarmScriptMeshUnqualified[] = "UNQUALIFIED";

/** One stored hop. The claimant is an ML-DSA-44 public key. */
struct SwarmScriptMeshHop {
    std::vector<unsigned char> claimant;
    std::vector<unsigned char> hash;
    int64_t expiry{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCRIPTMESH_TYPES_H
