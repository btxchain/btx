// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_SHARE_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_SHARE_H

#include <modelnet/swarm_cachepair/book.h>
#include <modelnet/swarm_cachepair/roster.h>

#include <string>

namespace modelnet {

/**
 * Record one share of page when it has two or more distinct members.
 * An unknown page is PAGE and records nothing. Fewer than two distinct
 * members is ALONE and records nothing. A second Share of a page
 * already recorded is REPLAY and does not add another record.
 * On success err is cleared. bytes stay where they were: this function
 * does not move bytes, take a CUDA buffer, or start a process.
 */
bool SwarmCachePairShare(const SwarmCachePairRoster& roster,
                         SwarmCachePairBook& book,
                         const std::string& page,
                         std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_SHARE_H
