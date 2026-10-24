// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/clock.h>

#include <cstdint>

namespace modelnet {

bool SwarmSandboxGateUntilRejected(int64_t until_ms)
{
    return until_ms < 0;
}

bool SwarmSandboxGateExpired(int64_t until_ms, int64_t now_ms)
{
    return now_ms >= until_ms;
}

bool SwarmSandboxGateLive(int64_t until_ms, int64_t now_ms)
{
    return now_ms < until_ms;
}

} // namespace modelnet
