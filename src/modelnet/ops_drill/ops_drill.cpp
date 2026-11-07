// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/ops_drill/ops_drill.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool DrillName(const std::string& name)
{
    return name == "retainer" || name == "triage" || name == "contain" ||
           name == "mitigate" || name == "patch" || name == "federate";
}

} // namespace

bool OpsDrill::stored(const std::string& name) const
{
    for (const std::string& row : m_stored) {
        if (row == name) return true;
    }
    return false;
}

int64_t OpsDrill::count() const
{
    return static_cast<int64_t>(m_stored.size());
}

void OpsDrill::Remember(const std::string& name)
{
    if (stored(name)) return;
    m_stored.push_back(name);
}

bool OpsDrill::Run(const std::string& name, const std::string& fixture, std::string& err)
{
    if (name.empty() || fixture.empty()) {
        err = OPS_DRILL_FIELD;
        return false;
    }
    if (!DrillName(name)) {
        err = OPS_DRILL_DRILL;
        return false;
    }
    if (fixture != "benign") {
        err = OPS_DRILL_FIXTURE;
        return false;
    }
    Remember(name);
    err.clear();
    return true;
}

bool OpsDrill::Contain(const std::string& fixture, std::string& err)
{
    if (fixture != "benign") {
        err = OPS_DRILL_BLAST;
        return false;
    }
    Remember("contain");
    err.clear();
    return true;
}

bool OpsDrill::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool OpsDrill::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool OpsDrill::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool OpsDrill::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
