// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOPENALTY_H
#define BTX_MODELNET_SWARM_NOPENALTY_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. stale_state asks for a stale-state
 * remedy. want_secp_penalty asks this note to apply a secp256k1 penalty.
 *
 * There is no secp256k1 penalty. secp_penalty stays false on every path.
 * Nothing is broadcast. No hostnames or IPs are used.
 */
struct SwarmPenaltyNote {
    std::string channel_id;
    bool stale_state{false};
    bool want_secp_penalty{false};
};

/**
 * Outcome of noting a channel penalty. secp_penalty stays false on every
 * path: there is no secp256k1 penalty and nothing is broadcast.
 */
struct SwarmPenaltyResult {
    bool secp_penalty{false};
    std::string code;
};

/**
 * Note a channel penalty without applying a secp256k1 penalty.
 * Order, first match wins: an empty channel_id is PENALTY.
 * want_secp_penalty is NO_PENALTY, even when stale_state is true.
 * stale_state is HASHLOCK and err is clear: stale state is a hashlock
 * remedy, not a penalty. Otherwise the note is NOTED and err is clear.
 * secp_penalty stays false on every path. Nothing is broadcast.
 */
SwarmPenaltyResult SwarmNotePenalty(const SwarmPenaltyNote& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOPENALTY_H
