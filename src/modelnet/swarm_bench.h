// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_BENCH_H
#define BTX_MODELNET_SWARM_BENCH_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmBenchSample {
    std::string device;
    std::string workload;
    double tokens_per_sec{0};
    int64_t vram_bytes{0};
    bool measurement_taken{false};
};

struct SwarmBenchRecord {
    bool recorded{false};
    bool multiplier_published{false};
    double tokens_per_sec{0};
    int64_t vram_bytes{0};
    std::string code;
};

/**
 * Records a bench sample. multiplier_published stays false: this function
 * does not publish a speedup multiplier.
 *
 * Order: an empty device or workload is BENCH. A sample that was not
 * measured is UNMEASURED and the stored numbers stay 0. A tokens_per_sec
 * that is not finite or is <= 0 is BENCH and the stored numbers stay 0.
 * vram_bytes <= 0 is BENCH and the stored numbers stay 0. Otherwise the
 * record is RECORDED, err is cleared, and the two numbers are copied.
 */
SwarmBenchRecord SwarmRecordBench(const SwarmBenchSample& sample, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_BENCH_H
