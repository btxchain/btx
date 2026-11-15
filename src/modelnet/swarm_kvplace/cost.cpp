// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/cost.h>

#include <modelnet/swarm_kvplace/codes.h>
#include <modelnet/swarm_kvplace/limits.h>

#include <cstdint>
#include <limits>
#include <string>

namespace modelnet {
namespace {

bool NegativeCost(std::int64_t recompute, std::int64_t idle, std::int64_t route, std::int64_t transfer,
                  std::int64_t missing_ppm, std::int64_t memory_pressure, std::int64_t copies)
{
    return recompute < 0 || idle < 0 || route < 0 || transfer < 0 || missing_ppm < 0 || memory_pressure < 0 ||
           copies < 0;
}

bool AddNonNegative(std::int64_t acc, std::int64_t part, std::int64_t& out)
{
    if (part < 0 || acc < 0) return false;
    if (part > std::numeric_limits<std::int64_t>::max() - acc) return false;
    out = acc + part;
    return true;
}

bool SharedExtra(std::int64_t missing_ppm, std::int64_t memory_pressure, std::int64_t copies, std::int64_t& extra)
{
    const std::int64_t from_ppm = missing_ppm / kSwarmKvPlaceMissingPpmDivisor;
    std::int64_t sum = 0;
    if (!AddNonNegative(sum, from_ppm, sum)) return false;
    if (!AddNonNegative(sum, memory_pressure, sum)) return false;
    if (!AddNonNegative(sum, copies, sum)) return false;
    extra = sum;
    return true;
}

bool ApplyContinuation(std::int64_t idle_cost, std::int64_t continuation, std::int64_t& out)
{
    if (continuation >= 0) {
        if (continuation >= idle_cost) {
            out = 0;
        } else {
            out = idle_cost - continuation;
        }
        return true;
    }
    // A negative continuation raises idle. It is not a PRESSURE input unless
    // the raised cost cannot be represented.
    if (continuation == std::numeric_limits<std::int64_t>::min()) return false;
    return AddNonNegative(idle_cost, -continuation, out);
}

} // namespace

bool SwarmKvPlaceAdjust(std::int64_t recompute, std::int64_t idle, std::int64_t route, std::int64_t transfer,
                        std::int64_t missing_ppm, std::int64_t memory_pressure, std::int64_t copies,
                        std::int64_t continuation, SwarmKvPlaceCosts& out, std::string& err)
{
    if (NegativeCost(recompute, idle, route, transfer, missing_ppm, memory_pressure, copies)) {
        err = SWARM_KVPLACE_PRESSURE;
        return false;
    }

    std::int64_t extra = 0;
    if (!SharedExtra(missing_ppm, memory_pressure, copies, extra)) {
        err = SWARM_KVPLACE_PRESSURE;
        return false;
    }

    SwarmKvPlaceCosts adjusted;
    if (!AddNonNegative(recompute, extra, adjusted.recompute) || !AddNonNegative(idle, extra, adjusted.idle) ||
        !AddNonNegative(route, extra, adjusted.route) || !AddNonNegative(transfer, extra, adjusted.transfer)) {
        err = SWARM_KVPLACE_PRESSURE;
        return false;
    }
    if (!ApplyContinuation(adjusted.idle, continuation, adjusted.idle)) {
        err = SWARM_KVPLACE_PRESSURE;
        return false;
    }

    out = adjusted;
    return true;
}

std::string SwarmKvPlacePick(const SwarmKvPlaceCosts& costs)
{
    std::string name = SWARM_KVPLACE_RECOMPUTE;
    std::int64_t best = costs.recompute;
    if (costs.idle < best) {
        best = costs.idle;
        name = SWARM_KVPLACE_IDLE;
    }
    if (costs.route < best) {
        best = costs.route;
        name = SWARM_KVPLACE_ROUTE;
    }
    if (costs.transfer < best) {
        name = SWARM_KVPLACE_TRANSFER;
    }
    return name;
}

} // namespace modelnet
