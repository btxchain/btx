// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn08/jrn08.h>
#include <modelnet/nt01/nt01.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "NT-NAT-001",
    "NT-NAT-002",
    "NT-NAT-003",
    "NT-NAT-004",
    "NT-NAT-005",
    "NT-NAT-006",
    "NT-FORK-001",
    "NT-FORK-002",
    "NT-FORK-003",
    "NT-FORK-004",
    "NT-FORK-005",
    "NT-FORK-006",
    "NT-PROF-001",
    "NT-PROF-002",
    "NT-PROF-003",
    "NT-PROF-004",
    "NT-PROF-005",
    "NT-PROF-006",
};

bool ApplyStep(Nt01& row, const char* id, const char* text, int64_t aux, bool flag,
               bool expect_ok, const char* expect_err, std::string& err)
{
    const bool ok = row.Apply(id, text, aux, flag, err);
    if (row.scenario_status() != "NOT_RUN") return false;
    if (expect_ok) return ok && err.empty();
    if (ok || expect_err == nullptr || err != expect_err) return false;
    return true;
}

} // namespace

bool Jrn08::Pass(std::string& err)
{
    Nt01 row;
    for (const char* id : kIds) {
        if (std::string(id) == "NT-FORK-004" || std::string(id) == "NT-FORK-005") {
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            if (row.stored(id) || !row.text(id).empty()) return false;
            if (row.scenario_status() != "NOT_RUN") return false;
            continue;
        }
        if (std::string(id) == "NT-PROF-006") {
            if (!ApplyStep(row, id, "gpu", static_cast<int64_t>(1), true, false, NIFDT_UNQUALIFIED, err)) return false;
        }
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, true, nullptr, err)) return false;
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_REPLAY, err)) return false;
        if (!ApplyStep(row, id, "s2", static_cast<int64_t>(1), true, false, "UNCHANGED", err)) return false;
        if (std::string(id) == "NT-PROF-006") {
            if (!ApplyStep(row, id, "gpu", static_cast<int64_t>(1), true, false, NIFDT_UNQUALIFIED, err)) return false;
            if (row.text(id) != "s1" || !row.stored(id)) return false;
        }
        if (row.scenario_status() != "NOT_RUN") return false;
    }
    if (row.scenario_status() != "NOT_RUN") return false;
    err.clear();
    return true;
}

bool Jrn08::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn08::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn08::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Jrn08::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn08::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
