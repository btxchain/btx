// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_DROP_H
#define BITCOIN_MODELNET_SWARM_DEDUP_DROP_H

#include <modelnet/swarm_dedup/index.h>

#include <string>

namespace modelnet {

/**
 * Remove one holder.
 * An unknown pair is MISSING and deletes nothing. A known pair is
 * removed and other holders of that piece id stay. No body is copied.
 */
bool SwarmPieceDedupDrop(SwarmPieceDedupIndex& index, const std::string& peer, const std::string& piece_id, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_DROP_H
