// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_benchrec.h>

namespace modelnet {

// A benchmark record publishes nothing unless a later runtime supplies a
// measurement. This function does not supply one.
SwarmBenchRecResult SwarmRecordBenchmark(const SwarmBenchRec& bench, std::string& err)
{
    SwarmBenchRecResult result;
    result.published = false;
    result.tokens = 0;
    result.ablation = bench.ablation;

    if (bench.bench_id.empty()) {
        result.code = "BENCH";
        err = "BENCH";
        return result;
    }
    if (bench.engine_name.empty() || bench.model_name.empty()) {
        result.code = "ENGINE";
        err = "ENGINE";
        return result;
    }
    if (!bench.hardware_present) {
        result.code = "UNQUALIFIED";
        err = "UNQUALIFIED";
        return result;
    }
    if (!bench.measurement_finite) {
        result.code = "UNMEASURED";
        err = "UNMEASURED";
        return result;
    }
    if (bench.reported_tokens != 0) {
        result.code = "RANGE";
        err = "RANGE";
        return result;
    }
    if (bench.want_publish) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
