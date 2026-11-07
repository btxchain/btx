// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag04.h>

#include <string>

namespace modelnet {

SwarmFlag04Result SwarmStageAccelerate(const SwarmFlag04& in, std::string& err)
{
    SwarmFlag04Result result;
    result.published = false;
    result.passed = false;
    result.bytes_moved = false;
    result.gain = 0;
    if (in.cache_id.empty()) {
        result.code = "CACHE";
        err = "CACHE";
        return result;
    }
    // Cache reuse must be measured against an uncached baseline.
    // No multiplier is published.
    if (!in.baseline_measured || !in.reuse_measured) {
        result.code = "UNMEASURED";
        err = "UNMEASURED";
        return result;
    }
    if (in.want_publish) {
        result.code = "HELD";
        err.clear();
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
