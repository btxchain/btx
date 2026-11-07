// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCACHE_H
#define BTX_MODELNET_SWARM_NOTNOCACHE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that a cache might publish a cache-hit rate.
 * cache_on records whether the cache is on. want_publish asks this note
 * to publish a hit rate.
 *
 * Cache off publishes no hit rate. published stays false and hit_ppm
 * stays 0 on every path.
 */
struct SwarmNotNoCache {
    std::string cache_id;
    bool cache_on{false};
    bool want_publish{false};
};

/**
 * Outcome of noting an unpublished cache-hit rate. published stays false
 * and hit_ppm stays 0 on every path: cache off publishes no hit rate.
 */
struct SwarmNotNoCacheResult {
    std::string code;
    bool published{false};
    int64_t hit_ppm{0};
};

/**
 * Note that no cache-hit rate is published.
 * Order, first match wins: an empty cache_id is CACHE. cache_on false is
 * UNMEASURED, even when want_publish is false. want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is cleared. published stays false
 * and hit_ppm stays 0 on every path. Cache off publishes no hit rate.
 */
SwarmNotNoCacheResult SwarmNoteNotNoCache(const SwarmNotNoCache& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCACHE_H
