// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablation.h>

namespace modelnet {

// An ablation publish request is held and publishes nothing.
SwarmAblationResult SwarmNoteAblation(const SwarmAblation& bench, std::string& err)
{
    SwarmAblationResult result;
    result.published = false;

    if (bench.bench_id.empty()) {
        result.code = "BENCH";
        err = "BENCH";
        result.published = false;
        return result;
    }
    if (bench.want_publish) {
        result.code = "HELD";
        err = "HELD";
        result.published = false;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.published = false;
    return result;
}

} // namespace modelnet
