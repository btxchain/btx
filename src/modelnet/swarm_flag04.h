// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG04_H
#define BTX_MODELNET_SWARM_FLAG04_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Flagship stage 4 accelerate: a local note that cache reuse might be
 * published. Cache reuse must be measured against an uncached baseline
 * before any reuse claim is eligible.
 *
 * This note does not publish a multiplier. published, passed, and
 * bytes_moved stay false on every path.
 */
struct SwarmFlag04 {
    std::string cache_id;
    bool baseline_measured{false};
    bool reuse_measured{false};
    bool want_publish{false};
    bool want_pass{false};
};

/**
 * Outcome of flagship stage 4 accelerate. published, passed, and
 * bytes_moved stay false on every path. gain stays 0: this note does
 * not publish a multiplier.
 */
struct SwarmFlag04Result {
    std::string code;
    bool published{false};
    bool passed{false};
    bool bytes_moved{false};
    int64_t gain{0};
};

/**
 * Note flagship stage 4 accelerate without publishing a multiplier.
 * Order, first match wins: an empty cache_id is CACHE. Missing
 * baseline_measured or reuse_measured is UNMEASURED, even when
 * want_publish is set. want_publish is HELD. want_pass is UNQUALIFIED.
 * Otherwise the note is NOTED.
 * published, passed, and bytes_moved stay false on every path.
 * gain stays 0. This note does not publish a multiplier.
 */
SwarmFlag04Result SwarmStageAccelerate(const SwarmFlag04& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG04_H
