// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_parallel/dt_parallel.h>

#include <cstdint>

namespace modelnet {
namespace {

bool DegreeProduct(int64_t dp, int64_t tp, int64_t pp, int64_t cp, int64_t ep, int64_t& out)
{
    const int64_t parts[5] = {dp, tp, pp, cp, ep};
    int64_t acc = 1;
    for (const int64_t part : parts) {
        if (part < 1) return false;
        if (acc > INT64_MAX / part) return false;
        acc *= part;
    }
    out = acc;
    return true;
}

} // namespace

bool DtParallel::Plan(int64_t dp, int64_t tp, int64_t pp, int64_t cp, int64_t ep, int64_t memory_bytes, int64_t capacity_bytes, std::string& err)
{
    if (m_frozen) {
        err = "FROZEN";
        return false;
    }
    int64_t product = 0;
    if (!DegreeProduct(dp, tp, pp, cp, ep, product)) {
        err = "RANK";
        return false;
    }
    if (memory_bytes > capacity_bytes) {
        err = "MEMORY";
        return false;
    }
    m_ranks = product;
    m_feasible = true;
    err.clear();
    return true;
}

bool DtParallel::Freeze(std::string& err)
{
    if (!m_feasible) {
        err = "PLAN";
        return false;
    }
    m_frozen = true;
    err.clear();
    return true;
}

bool DtParallel::Shrink(int64_t n, std::string& err)
{
    (void)n;
    if (m_frozen) {
        err = "FROZEN";
        return false;
    }
    err = "PLAN";
    return false;
}

bool DtParallel::Commit(std::string& err)
{
    if (!m_feasible || !m_frozen) {
        err = "PLAN";
        return false;
    }
    err.clear();
    return true;
}

bool DtParallel::GpuCollective(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
