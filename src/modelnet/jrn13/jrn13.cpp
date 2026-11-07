// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn13/jrn13.h>
#include <modelnet/dtat02/dtat02.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "DT-AT-GRD-001",
    "DT-AT-GRD-002",
    "DT-AT-GRD-003",
    "DT-AT-GRD-004",
    "DT-AT-GRD-005",
    "DT-AT-GRD-006",
    "DT-AT-GRD-007",
    "DT-AT-GRD-008",
    "DT-AT-PAR-001",
    "DT-AT-PAR-002",
    "DT-AT-PAR-003",
    "DT-AT-PAR-004",
    "DT-AT-PAR-005",
    "DT-AT-PAR-006",
    "DT-AT-PAR-007",
    "DT-AT-PAR-008",
};

bool ApplyStep(Dtat02& row, const char* id, const char* text, int64_t aux, bool flag,
               bool expect_ok, const char* expect_err, std::string& err)
{
    const bool ok = row.Apply(id, text, aux, flag, err);
    if (row.scenario_status() != "NOT_RUN") return false;
    if (expect_ok) return ok && err.empty();
    if (ok || expect_err == nullptr || err != expect_err) return false;
    return true;
}

} // namespace

bool Jrn13::Pass(std::string& err)
{
    Dtat02 row;
    if (NifDtEngineLinked("dualpipe")) return false;
    for (const char* id : kIds) {
        if (std::string(id) == "DT-AT-PAR-006") {
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            if (!ApplyStep(row, id, "s2", static_cast<int64_t>(100), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            if (row.stored(id)) return false;
            if (row.scenario_status() != "NOT_RUN") return false;
            continue;
        }
        if (std::string(id) == "DT-AT-GRD-002") {
            if (!ApplyStep(row, id, "dualpipe", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            if (row.stored(id)) return false;
        }
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, true, nullptr, err)) return false;
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_REPLAY, err)) return false;
        if (std::string(id) == "DT-AT-GRD-003") {
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(0), true, false, NIFDT_REPLAY, err)) return false;
        }
        if (!ApplyStep(row, id, "s2", static_cast<int64_t>(1), true, false, "UNCHANGED", err)) return false;
        if (row.scenario_status() != "NOT_RUN") return false;
    }
    if (row.scenario_status() != "NOT_RUN") return false;
    if (row.text("DT-AT-GRD-002") == "dualpipe") return false;
    err.clear();
    return true;
}

bool Jrn13::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn13::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn13::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Jrn13::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn13::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
