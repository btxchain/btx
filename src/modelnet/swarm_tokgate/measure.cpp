// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/measure.h>

#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/codes.h>
#include <modelnet/swarm_tokgate/latency.h>
#include <modelnet/swarm_tokgate/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmTokenGateMeasureRefuse(const SwarmTokenGateBook& book,
                                 const SwarmTokenGateLatency& latency,
                                 const std::string& session,
                                 std::string& err)
{
    if (!book.open(session)) {
        err = kSwarmTokenGateSession;
        return false;
    }
    const int64_t ttft = latency.ttft_ms();
    const int64_t p50 = latency.p50_ms();
    const int64_t p95 = latency.p95_ms();
    if (latency.measured()) {
        err = kSwarmTokenGateNotMeasured;
        return false;
    }
    if (ttft != kSwarmTokenGateUnmeasuredMs || p50 != kSwarmTokenGateUnmeasuredMs ||
        p95 != kSwarmTokenGateUnmeasuredMs) {
        err = kSwarmTokenGateNotMeasured;
        return false;
    }
    err = kSwarmTokenGateNotMeasured;
    return false;
}

} // namespace modelnet
