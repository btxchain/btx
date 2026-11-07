// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn16/jrn16.h>
#include <modelnet/dtat05/dtat05.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "DT-AT-WAN-001",
    "DT-AT-WAN-002",
    "DT-AT-WAN-003",
    "DT-AT-WAN-004",
    "DT-AT-WAN-005",
    "DT-AT-WAN-006",
    "DT-AT-WAN-007",
    "DT-AT-WAN-008",
    "DT-AT-SEC-001",
    "DT-AT-SEC-002",
    "DT-AT-SEC-003",
    "DT-AT-SEC-004",
    "DT-AT-SEC-005",
    "DT-AT-SEC-006",
    "DT-AT-SEC-007",
    "DT-AT-SEC-008",
};

bool ApplyStep(Dtat05& row, const char* id, const char* text, int64_t aux, bool flag,
               bool expect_ok, const char* expect_err, std::string& err)
{
    const bool ok = row.Apply(id, text, aux, flag, err);
    if (row.scenario_status() != "NOT_RUN") return false;
    if (expect_ok) return ok && err.empty();
    if (ok || expect_err == nullptr || err != expect_err) return false;
    return true;
}

} // namespace

bool Jrn16::Pass(std::string& err)
{
    Dtat05 row;
    for (const char* id : kIds) {
        if (std::string(id) == "DT-AT-WAN-001") {
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_NO_ROUTE, err)) return false;
            if (!ApplyStep(row, id, "s2", static_cast<int64_t>(1), true, false, NIFDT_NO_ROUTE, err)) return false;
            if (row.scenario_status() != "NOT_RUN") return false;
            continue;
        }
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, true, nullptr, err)) return false;
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(0), true, false, NIFDT_REPLAY, err)) return false;
        if (!ApplyStep(row, id, "s2", static_cast<int64_t>(100), true, false, "UNCHANGED", err)) return false;
        if (row.scenario_status() != "NOT_RUN") return false;
    }
    if (row.scenario_status() != "NOT_RUN") return false;
    err.clear();
    return true;
}

bool Jrn16::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn16::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn16::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Jrn16::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn16::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
