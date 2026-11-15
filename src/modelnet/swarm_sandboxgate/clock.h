// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_CLOCK_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_CLOCK_H

#include <cstdint>

namespace modelnet {

/**
 * until_ms below 0 cannot be stored.
 * Zero is a usable deadline. This does not read a clock.
 */
bool SwarmSandboxGateUntilRejected(int64_t until_ms);

/**
 * now_ms >= until_ms.
 * Equality is expired. The action is not recorded when every match is expired.
 */
bool SwarmSandboxGateExpired(int64_t until_ms, int64_t now_ms);

/**
 * now_ms < until_ms.
 * now_ms == until_ms - 1 is live when until_ms is stored.
 */
bool SwarmSandboxGateLive(int64_t until_ms, int64_t now_ms);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_CLOCK_H
