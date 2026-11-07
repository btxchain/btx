// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_BENCHREC_H
#define BTX_MODELNET_SWARM_BENCHREC_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmBenchRec {
    std::string bench_id;
    std::string engine_name;
    std::string model_name;
    bool hardware_present{false};
    bool ablation{false};
    bool measurement_finite{false};
    int64_t reported_tokens{0};
    bool want_publish{false};
};

struct SwarmBenchRecResult {
    std::string code;
    bool published{false};
    int64_t tokens{0};
    bool ablation{false};
};

/**
 * Records a benchmark request. published stays false and tokens stay 0.
 * A benchmark record publishes nothing unless a later runtime supplies a
 * measurement. This function does not supply one.
 *
 * Order: an empty bench_id is BENCH. An empty engine_name or model_name
 * is ENGINE. hardware_present false is UNQUALIFIED even when
 * measurement_finite is true. measurement_finite false is UNMEASURED.
 * reported_tokens other than 0 is RANGE: a caller-supplied count is not a
 * measurement. want_publish true is HELD. Otherwise the code is NOTED and
 * err is cleared. ablation is copied on every path.
 */
SwarmBenchRecResult SwarmRecordBenchmark(const SwarmBenchRec& bench, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_BENCHREC_H
