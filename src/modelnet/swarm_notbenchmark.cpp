// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notbenchmark.h>

#include <string>

namespace modelnet {

SwarmNotBenchmarkResult SwarmNoteNotBenchmark(const SwarmNotBenchmark& note, std::string& err)
{
    SwarmNotBenchmarkResult result;
    result.published = false;
    result.measured = false;
    // A caller-supplied tokens_per_sec is not a hardware benchmark.
    if (note.node_id.empty() || note.tokens_per_sec < 0) {
        result.code = "RATE";
        result.published = false;
        result.measured = false;
        err = "RATE";
        return result;
    }
    // Publishing is refused even when the caller supplied a positive rate.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.measured = false;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.measured = false;
    err.clear();
    return result;
}

} // namespace modelnet
