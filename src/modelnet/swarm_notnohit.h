// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHIT_H
#define BTX_MODELNET_SWARM_NOTNOHIT_H

#include <string>

namespace modelnet {

/**
 * A local note that a cache might publish a cache-hit rate.
 * want_publish asks this note to publish one.
 *
 * No cache-hit rate is published by this note.
 * published stays false and hit_ppm stays 0 on every path.
 */
struct SwarmNotNoHit {
    std::string cache_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an unpublished cache-hit rate. published stays false
 * and hit_ppm stays 0 on every path: no cache-hit rate is published by
 * this note.
 */
struct SwarmNotNoHitResult {
    std::string code;
    bool published{false};
    int hit_ppm{0};
};

/**
 * Note that no cache-hit rate is published.
 * Order, first match wins: an empty cache_id is CACHE. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is cleared.
 * published stays false and hit_ppm stays 0 on every path. No cache-hit
 * rate is published by this note.
 */
SwarmNotNoHitResult SwarmNoteNotNoHit(const SwarmNotNoHit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHIT_H
