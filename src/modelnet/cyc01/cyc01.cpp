// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/cyc01/cyc01.h>
#include <modelnet/node_cycle/node_cycle.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

bool Cyc01::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    modelnet::NodeCycle cycle;
    if (!cycle.Run(err)) return false;
    if (cycle.steps().size() != static_cast<std::size_t>(12)) {
        err = "STEPS";
        return false;
    }
    if (cycle.generation() != static_cast<int64_t>(0)) {
        err = "GENERATION";
        return false;
    }
    if (cycle.passed()) {
        err = "PASSED";
        return false;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Cyc01::Hosts(int64_t n, std::string& err)
{
    if (n == static_cast<int64_t>(1)) {
        err.clear();
        return true;
    }
    err = "HOSTS";
    return false;
}

bool Cyc01::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Cyc01::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Cyc01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Cyc01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
