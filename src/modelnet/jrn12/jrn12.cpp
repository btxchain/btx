// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn12/jrn12.h>
#include <modelnet/dtat01/dtat01.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "DT-AT-EVD-001",
    "DT-AT-EVD-002",
    "DT-AT-EVD-003",
    "DT-AT-EVD-004",
    "DT-AT-EVD-005",
    "DT-AT-EVD-006",
    "DT-AT-EVD-007",
    "DT-AT-EVD-008",
    "DT-AT-NAT-001",
    "DT-AT-NAT-002",
    "DT-AT-NAT-003",
    "DT-AT-NAT-004",
    "DT-AT-NAT-005",
    "DT-AT-NAT-006",
    "DT-AT-NAT-007",
    "DT-AT-NAT-008",
};

bool ApplyStep(Dtat01& row, const char* id, const char* text, int64_t aux, bool flag,
               bool expect_ok, const char* expect_err, std::string& err)
{
    const bool ok = row.Apply(id, text, aux, flag, err);
    if (row.scenario_status() != "NOT_RUN") return false;
    if (expect_ok) return ok && err.empty();
    if (ok || expect_err == nullptr || err != expect_err) return false;
    return true;
}

} // namespace

bool Jrn12::Pass(std::string& err)
{
    Dtat01 row;
    for (const char* id : kIds) {
        if (std::string(id) == "DT-AT-NAT-003") {
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(0), true, false, "EXPIRED", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, true, nullptr, err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(0), true, false, "EXPIRED", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_REPLAY, err)) return false;
            if (!ApplyStep(row, id, "s2", static_cast<int64_t>(100), true, false, "UNCHANGED", err)) return false;
            if (!ApplyStep(row, id, "s2", static_cast<int64_t>(0), true, false, "EXPIRED", err)) return false;
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

bool Jrn12::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn12::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn12::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Jrn12::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn12::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
