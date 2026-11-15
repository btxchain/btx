// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVBENCH_H
#define BTX_MODELNET_SWARM_KVBENCH_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A KV benchmark record. bench_id names the benchmark. measured is true
 * when the benchmark was measured. want_publish asks this note to publish
 * it.
 *
 * An unmeasured KV benchmark is not published.
 */
struct SwarmKvBench {
    std::string bench_id;
    bool measured{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a KV benchmark. published stays false and tokens stay
 * 0 on every path.
 */
struct SwarmKvBenchResult {
    std::string code;
    bool published{false};
    int64_t tokens{0};
};

/**
 * Note a KV benchmark. An unmeasured KV benchmark is not published.
 * Order, first match wins: an empty bench_id is BENCH. measured false is
 * NOT_PUBLISHED, even when want_publish is false. want_publish true is
 * HELD. Otherwise the code is NOTED and err is cleared.
 * published stays false and tokens stay 0 on every path.
 */
SwarmKvBenchResult SwarmNoteKvBench(const SwarmKvBench& bench, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVBENCH_H
