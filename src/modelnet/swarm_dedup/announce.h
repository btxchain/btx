// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_ANNOUNCE_H
#define BITCOIN_MODELNET_SWARM_DEDUP_ANNOUNCE_H

#include <modelnet/swarm_dedup/index.h>

#include <string>

namespace modelnet {

/**
 * Record one opaque peer as a holder of one opaque piece id.
 * Refusals return false, set err, and leave the index unchanged.
 * A new holder returns true and clears err. The piece body is not stored.
 */
bool SwarmPieceDedupAnnounce(SwarmPieceDedupIndex& index, const std::string& peer, const std::string& piece_id, bool is_private, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_ANNOUNCE_H
