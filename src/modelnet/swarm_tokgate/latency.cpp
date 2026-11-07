// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/latency.h>

#include <modelnet/swarm_tokgate/limits.h>

#include <cstdint>

namespace modelnet {

int64_t SwarmTokenGateLatency::ttft_ms() const
{
    return kSwarmTokenGateUnmeasuredMs;
}

int64_t SwarmTokenGateLatency::p50_ms() const
{
    return kSwarmTokenGateUnmeasuredMs;
}

int64_t SwarmTokenGateLatency::p95_ms() const
{
    return kSwarmTokenGateUnmeasuredMs;
}

bool SwarmTokenGateLatency::measured() const
{
    return kSwarmTokenGateMeasured;
}

} // namespace modelnet
