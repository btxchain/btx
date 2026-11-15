// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvbench.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmKvBenchResult SwarmNoteKvBench(const SwarmKvBench& bench, std::string& err)
{
    // An unmeasured KV benchmark is not published.
    SwarmKvBenchResult result;
    result.published = false;
    result.tokens = 0;
    if (bench.bench_id.empty()) {
        result.code = "BENCH";
        result.published = false;
        result.tokens = 0;
        err = "BENCH";
        return result;
    }
    if (!bench.measured) {
        result.code = "NOT_PUBLISHED";
        result.published = false;
        result.tokens = 0;
        err = "NOT_PUBLISHED";
        return result;
    }
    if (bench.want_publish) {
        result.code = "HELD";
        result.published = false;
        result.tokens = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.tokens = 0;
    err.clear();
    return result;
}

} // namespace modelnet
