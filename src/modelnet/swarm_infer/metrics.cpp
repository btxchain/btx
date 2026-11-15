// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_infer/metrics.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmInferMetrics SwarmInferMetricsFromText(const std::string& text)
{
    // Streamed text is not a tok/s, p50, p95, or TTFT. Do not read a number
    // out of the text, including text that names those counters.
    (void)text;
    SwarmInferMetrics metrics;
    metrics.tokens_per_sec = -1.0;
    metrics.p50_ms = -1.0;
    metrics.p95_ms = -1.0;
    metrics.ttft_ms = -1.0;
    metrics.bytes_moved = 0;
    metrics.published = false;
    return metrics;
}

} // namespace modelnet
