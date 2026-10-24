// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_PULL_H
#define BITCOIN_MODELNET_SWARM_DEDUP_PULL_H

#include <modelnet/swarm_dedup/index.h>

#include <string>

namespace modelnet {

/**
 * Decide why a requester does not receive a piece.
 * Every path returns false. No holder is MISSING. The requester as the
 * only holder is ALONE. Any other holder is HELD. The index is not
 * modified. Holding is not a transfer, and no body is copied.
 */
bool SwarmPieceDedupPull(const SwarmPieceDedupIndex& index, const std::string& requester, const std::string& piece_id, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_PULL_H
