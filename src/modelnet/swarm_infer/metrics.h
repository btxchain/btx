// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_INFER_METRICS_H
#define BTX_MODELNET_SWARM_INFER_METRICS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Unmeasured inference counters.
 * tokens_per_sec, p50_ms, p95_ms, and ttft_ms stay -1.
 * bytes_moved stays 0. published stays false.
 * Streamed text is not a tok/s, p50, p95, or TTFT.
 */
struct SwarmInferMetrics {
    double tokens_per_sec{-1.0};
    double p50_ms{-1.0};
    double p95_ms{-1.0};
    double ttft_ms{-1.0};
    int64_t bytes_moved{0};
    bool published{false};
};

/**
 * Observe text without turning it into a rate or a latency.
 * The characters of text are not parsed. The returned counters are the
 * unmeasured sentinels above.
 */
SwarmInferMetrics SwarmInferMetricsFromText(const std::string& text);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_INFER_METRICS_H
