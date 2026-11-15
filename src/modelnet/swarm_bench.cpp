// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bench.h>

#include <cmath>

namespace modelnet {

SwarmBenchRecord SwarmRecordBench(const SwarmBenchSample& sample, std::string& err)
{
    SwarmBenchRecord record;
    record.recorded = false;
    record.multiplier_published = false;
    if (sample.device.empty() || sample.workload.empty()) {
        record.code = "BENCH";
        err = "BENCH";
        return record;
    }
    if (!sample.measurement_taken) {
        record.code = "UNMEASURED";
        err = "UNMEASURED";
        return record;
    }
    if (!std::isfinite(sample.tokens_per_sec) || sample.tokens_per_sec <= 0) {
        record.code = "BENCH";
        err = "BENCH";
        return record;
    }
    if (sample.vram_bytes <= 0) {
        record.code = "BENCH";
        err = "BENCH";
        return record;
    }
    record.recorded = true;
    record.multiplier_published = false;
    record.code = "RECORDED";
    err.clear();
    record.tokens_per_sec = sample.tokens_per_sec;
    record.vram_bytes = sample.vram_bytes;
    return record;
}

} // namespace modelnet
