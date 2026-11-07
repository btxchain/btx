// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_CODES_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_CODES_H

namespace modelnet {

/** Empty claim. Nothing is stored. */
inline constexpr char kSwarmCheckpointTrustClaim[] = "CLAIM";

/** A second Trust of a claim already stored. The first claim stays. */
inline constexpr char kSwarmCheckpointTrustReplay[] = "REPLAY";

/**
 * The claim is stored and trust is refused.
 * A checkpoint-only claim is not lineage authority.
 * trusted() stays false.
 */
inline constexpr char kSwarmCheckpointTrustNotTrust[] = "NOT_TRUST";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_CODES_H
