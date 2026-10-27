// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn11/jrn11.h>
#include <modelnet/nt04/nt04.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "NT-DATA-005",
    "NT-ECON-001",
    "NT-ECON-002",
    "NT-ECON-003",
    "NT-ECON-004",
    "NT-QA-001",
    "NT-QA-002",
    "NT-QA-003",
    "NT-QA-004",
    "NT-QA-005",
    "NT-QA-006",
    "NT-QA-007",
    "NT-GOV-001",
    "NT-GOV-002",
    "NT-GOV-003",
    "NT-GOV-004",
};

const char* const kEngines[] = {
    "vllm",
    "sglang",
    "lmcache",
    "nixl",
    "mooncake",
    "rdma",
    "deepinfer",
    "dualpipe",
    "fp8",
    "fp4",
};

bool ApplyStep(Nt04& row, const char* id, const char* text, int64_t aux, bool flag,
               bool expect_ok, const char* expect_err, std::string& err)
{
    const bool ok = row.Apply(id, text, aux, flag, err);
    if (expect_ok) return ok && err.empty();
    if (ok || expect_err == nullptr || err != expect_err) return false;
    return true;
}

} // namespace

bool Jrn11::Pass(std::string& err)
{
    Nt04 row;
    if (!ApplyStep(row, "", "", static_cast<int64_t>(0), true, false, "ID", err)) return false;
    if (!ApplyStep(row, "NT-NO-SUCH", "s1", static_cast<int64_t>(1), true, false, "ID", err)) return false;
    for (const char* id : kIds) {
        if (std::string(id) == "NT-DATA-005") {
            if (!ApplyStep(row, id, "", static_cast<int64_t>(-1), false, false, "FIELD", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(-1), true, false, "BOUND", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(101), false, false, "CAP", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(0), false, false, "ABSENT", err)) return false;
        }
        if (std::string(id) == "NT-ECON-001") {
            for (const char* name : kEngines) {
                if (!ApplyStep(row, id, name, static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            }
            if (!ApplyStep(row, id, "s1 private", static_cast<int64_t>(1), true, false, NIFDT_PRIVATE_DATA, err)) return false;
        }
        if (std::string(id) == "NT-QA-007") {
            if (!ApplyStep(row, id, "", static_cast<int64_t>(1), true, false, "FIELD", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(101), true, false, "CAP", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), false, false, "ABSENT", err)) return false;
            if (!ApplyStep(row, id, "vllm", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            if (!ApplyStep(row, id, "private", static_cast<int64_t>(1), true, false, NIFDT_PRIVATE_DATA, err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_UNQUALIFIED, err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_UNQUALIFIED, err)) return false;
            continue;
        }
        if (std::string(id) == "NT-ECON-004") {
            if (!ApplyStep(row, id, "", static_cast<int64_t>(1), true, false, "FIELD", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(101), true, false, "CAP", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), false, false, "ABSENT", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_AUTOMATIC_SPEND, err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_AUTOMATIC_SPEND, err)) return false;
            continue;
        }
        if (std::string(id) == "NT-GOV-004") {
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_AUTOMATIC_SPEND, err)) return false;
            continue;
        }
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, true, nullptr, err)) return false;
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_REPLAY, err)) return false;
        if (!ApplyStep(row, id, "s2", static_cast<int64_t>(1), true, false, "UNCHANGED", err)) return false;
    }
    err.clear();
    return true;
}

bool Jrn11::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn11::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn11::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Jrn11::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn11::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
