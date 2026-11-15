// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn14/jrn14.h>
#include <modelnet/dtat03/dtat03.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "DT-AT-OPT-001",
    "DT-AT-OPT-002",
    "DT-AT-OPT-003",
    "DT-AT-OPT-004",
    "DT-AT-OPT-005",
    "DT-AT-OPT-006",
    "DT-AT-OPT-007",
    "DT-AT-OPT-008",
    "DT-AT-DAT-001",
    "DT-AT-DAT-002",
    "DT-AT-DAT-003",
    "DT-AT-DAT-004",
    "DT-AT-DAT-005",
    "DT-AT-DAT-006",
    "DT-AT-DAT-007",
    "DT-AT-DAT-008",
};

bool Step(Dtat03& row, const char* id, const char* text, int64_t aux, bool flag, bool expect_ok, const char* expect_err, std::string& err)
{
    const bool ok = row.Apply(id, text, aux, flag, err);
    if (row.scenario_status() != "NOT_RUN") return false;
    if (expect_ok) return ok && err.empty();
    return !ok && expect_err != nullptr && err == expect_err;
}

bool Unqualified(const char* id)
{
    return std::string(id) == "DT-AT-OPT-005" || std::string(id) == "DT-AT-OPT-006";
}

} // namespace

bool Jrn14::Pass(std::string& err)
{
    Dtat03 row;
    for (const char* id : kIds) {
        if (!Step(row, id, "s1", static_cast<int64_t>(1), false, false, "ABSENT", err)) return false;
        if (row.stored(id)) return false;
        if (Unqualified(id)) {
            if (!Step(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_UNQUALIFIED, err)) return false;
            if (row.stored(id)) return false;
            continue;
        }
        if (!Step(row, id, "vllm", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
        if (!Step(row, id, "s1", static_cast<int64_t>(1), true, true, nullptr, err)) return false;
        if (!Step(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_REPLAY, err)) return false;
        if (!Step(row, id, "s2", static_cast<int64_t>(1), true, false, "UNCHANGED", err)) return false;
        if (row.text(id) != "s1") return false;
        if (row.scenario_status() != "NOT_RUN") return false;
    }
    err.clear();
    return row.scenario_status() == "NOT_RUN" && !row.gpu_passed() && !row.windows_passed();
}

bool Jrn14::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn14::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn14::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Jrn14::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn14::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
