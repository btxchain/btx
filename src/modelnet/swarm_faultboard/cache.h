// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_CACHE_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_CACHE_H

#include <modelnet/swarm_faultboard/quiet.h>

#include <string>

namespace modelnet {

/**
 * Cache owner loss, a truncated cache, a partial piece, and a revoked read.
 * Each refusal leaves bytes_moved() at 0.
 */
bool SwarmFaultCacheOwnerGone(const SwarmFaultQuiet& quiet, std::string& err);
bool SwarmFaultTruncatedCache(const SwarmFaultQuiet& quiet, std::string& err);
bool SwarmFaultPartialPiece(const SwarmFaultQuiet& quiet, std::string& err);
bool SwarmFaultRevokedRead(const SwarmFaultQuiet& quiet, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_CACHE_H
