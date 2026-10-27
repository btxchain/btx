// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCACHEHIT_H
#define BTX_MODELNET_SWARM_NOTCACHEHIT_H

#include <string>

namespace modelnet {

/**
 * A local note that a node might publish a cache-hit rate.
 * want_publish asks this note to publish one.
 *
 * No cache-hit rate has been measured, so this note does not publish one.
 * published stays false on every path.
 */
struct SwarmNotCacheHit {
    std::string node_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an unmeasured cache-hit rate. published stays false on
 * every path: no cache-hit rate has been measured, so this note does not
 * publish one.
 */
struct SwarmNotCacheHitResult {
    std::string code;
    bool published{false};
};

/**
 * Note that no cache-hit rate is published.
 * Order, first match wins: an empty node_id is HIT. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false on every path. No cache-hit rate has been measured,
 * so this note does not publish one.
 */
SwarmNotCacheHitResult SwarmNoteNotCacheHit(const SwarmNotCacheHit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCACHEHIT_H
