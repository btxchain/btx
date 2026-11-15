// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCACHEGAIN_H
#define BTX_MODELNET_SWARM_NOTCACHEGAIN_H

#include <string>

namespace modelnet {

/**
 * A local note that a node might publish a cache-reuse improvement.
 * want_publish asks this note to publish one.
 *
 * No measured cache-reuse improvement against an uncached baseline exists,
 * so this note does not publish one. published stays false on every path.
 */
struct SwarmNotCacheGain {
    std::string page_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an unmeasured cache-reuse improvement. published stays
 * false on every path: no measured cache-reuse improvement against an
 * uncached baseline exists, so this note does not publish one.
 */
struct SwarmNotCacheGainResult {
    std::string code;
    bool published{false};
};

/**
 * Note that no cache-reuse improvement is published.
 * Order, first match wins: an empty page_id is CACHE. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false on every path. No measured cache-reuse improvement
 * against an uncached baseline exists, so this note does not publish one.
 */
SwarmNotCacheGainResult SwarmNoteNotCacheGain(const SwarmNotCacheGain& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCACHEGAIN_H
