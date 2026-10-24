// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_pressure.h>

#include <limits>

namespace modelnet {
namespace {

bool SumCost(int64_t milliseconds, int missing_ppm, int memory_pressure, int copies, int64_t& out)
{
    const int64_t parts[] = {milliseconds, static_cast<int64_t>(missing_ppm) / 1000, memory_pressure, copies};
    int64_t acc = 0;
    for (int64_t part : parts) {
        if (part > 0 && acc > std::numeric_limits<int64_t>::max() - part) return false;
        acc += part;
    }
    out = acc;
    return true;
}

SwarmPressureChoice Pressure(std::string& err)
{
    err = "PRESSURE";
    return {};
}

} // namespace

SwarmPressureChoice SwarmChoosePressured(int64_t recompute_ms, int64_t transfer_ms, int64_t route_ms,
                                         int64_t idle_uncached_ms, int missing_ppm, int memory_pressure, int copies,
                                         int continuation_ppm, bool engine_present, std::string& err)
{
    const int64_t times[] = {recompute_ms, transfer_ms, route_ms, idle_uncached_ms};
    for (int64_t time : times) {
        if (time < 0) return Pressure(err);
    }
    if (missing_ppm < 0 || memory_pressure < 0 || copies < 0 || continuation_ppm < 0) return Pressure(err);

    int64_t recompute = 0;
    int64_t transfer = 0;
    int64_t route = 0;
    int64_t idle = 0;
    if (!SumCost(recompute_ms, missing_ppm, memory_pressure, copies, recompute) ||
        !SumCost(transfer_ms, missing_ppm, memory_pressure, copies, transfer) ||
        !SumCost(route_ms, missing_ppm, memory_pressure, copies, route) ||
        !SumCost(idle_uncached_ms, missing_ppm, memory_pressure, copies, idle)) {
        return Pressure(err);
    }
    const int64_t reduction = static_cast<int64_t>(continuation_ppm) / 1000;
    if (reduction >= idle) {
        idle = 0;
    } else {
        idle -= reduction;
    }

    struct Candidate {
        const char* name;
        int64_t cost;
    };
    const Candidate candidates[] = {
        {"RECOMPUTE_LOCAL", recompute},
        {"IDLE_UNCACHED", idle},
        {"ROUTE_TO_OWNER", route},
        {"TRANSFER_KV", transfer},
    };
    const Candidate* best = &candidates[0];
    for (const Candidate& candidate : candidates) {
        if (candidate.cost < best->cost) best = &candidate;
    }

    SwarmPressureChoice out;
    out.choice = best->name;
    out.cost = best->cost;
    out.bytes_moved = false;
    out.measured_benchmark = false;
    if (out.choice == "TRANSFER_KV") {
        out.code = engine_present ? "LOCAL" : "ENGINE_ABSENT";
    }
    err.clear();
    return out;
}

} // namespace modelnet
