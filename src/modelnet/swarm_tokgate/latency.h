// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_LATENCY_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_LATENCY_H

#include <cstdint>

namespace modelnet {

/**
 * Latency inspectors for this plane.
 * ttft_ms(), p50_ms(), and p95_ms() stay -1.
 * measured() stays false.
 * There is no method that marks ttft, p50, or p95 measured.
 */
class SwarmTokenGateLatency {
public:
    int64_t ttft_ms() const;
    int64_t p50_ms() const;
    int64_t p95_ms() const;
    bool measured() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_LATENCY_H
