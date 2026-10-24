// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn10/jrn10.h>
#include <modelnet/nt03/nt03.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "NT-LAN-005",
    "NT-LAN-006",
    "NT-LAN-007",
    "NT-LAN-008",
    "NT-ISL-001",
    "NT-ISL-002",
    "NT-ISL-003",
    "NT-ISL-004",
    "NT-ISL-005",
    "NT-PKG-001",
    "NT-PKG-002",
    "NT-PKG-003",
    "NT-PKG-004",
    "NT-PKG-005",
    "NT-DATA-001",
    "NT-DATA-002",
    "NT-DATA-003",
    "NT-DATA-004",
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

bool ApplyStep(Nt03& row, const char* id, const char* text, int64_t aux, bool flag,
               bool expect_ok, const char* expect_err, std::string& err)
{
    const bool ok = row.Apply(id, text, aux, flag, err);
    if (expect_ok) return ok && err.empty();
    if (ok || expect_err == nullptr || err != expect_err) return false;
    return true;
}

} // namespace

bool Jrn10::Pass(std::string& err)
{
    Nt03 row;
    for (const char* id : kIds) {
        if (std::string(id) == "NT-PKG-001") {
            if (!ApplyStep(row, id, "", static_cast<int64_t>(1), true, false, "FIELD", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(-1), true, false, "BOUND", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(101), true, false, "CAP", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), false, false, "ABSENT", err)) return false;
            if (!ApplyStep(row, id, "vllm", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            if (!ApplyStep(row, id, "private note", static_cast<int64_t>(1), true, false, NIFDT_PRIVATE_DATA, err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_UNQUALIFIED, err)) return false;
            if (!ApplyStep(row, id, "s2", static_cast<int64_t>(100), true, false, NIFDT_UNQUALIFIED, err)) return false;
            if (!ApplyStep(row, id, "wan", static_cast<int64_t>(1), true, false, NIFDT_UNQUALIFIED, err)) return false;
            continue;
        }
        if (std::string(id) == "NT-LAN-005") {
            if (!ApplyStep(row, id, "", static_cast<int64_t>(1), true, false, "FIELD", err)) return false;
            if (!ApplyStep(row, id, "wan", static_cast<int64_t>(-1), true, false, "BOUND", err)) return false;
            if (!ApplyStep(row, id, "wan", static_cast<int64_t>(101), true, false, "CAP", err)) return false;
            if (!ApplyStep(row, id, "wan", static_cast<int64_t>(1), false, false, "ABSENT", err)) return false;
            if (!ApplyStep(row, id, "vllm", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            if (!ApplyStep(row, id, "private wan", static_cast<int64_t>(1), true, false, NIFDT_PRIVATE_DATA, err)) return false;
            if (!ApplyStep(row, id, "wan", static_cast<int64_t>(1), true, false, NIFDT_NO_ROUTE, err)) return false;
            if (!ApplyStep(row, id, "wan", static_cast<int64_t>(0), true, false, NIFDT_NO_ROUTE, err)) return false;
        }
        if (std::string(id) == "NT-LAN-006") {
            if (!ApplyStep(row, id, "", static_cast<int64_t>(-1), false, false, "FIELD", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(-1), true, false, "BOUND", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(101), false, false, "CAP", err)) return false;
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(0), false, false, "ABSENT", err)) return false;
            if (!ApplyStep(row, id, "fp8", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            for (const char* name : kEngines) {
                if (!ApplyStep(row, id, name, static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            }
            if (!ApplyStep(row, id, "private note", static_cast<int64_t>(1), true, false, NIFDT_PRIVATE_DATA, err)) return false;
        }
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, true, nullptr, err)) return false;
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_REPLAY, err)) return false;
        if (!ApplyStep(row, id, "s2", static_cast<int64_t>(1), true, false, "UNCHANGED", err)) return false;
        if (std::string(id) == "NT-LAN-005") {
            if (!ApplyStep(row, id, "wan", static_cast<int64_t>(1), true, false, NIFDT_NO_ROUTE, err)) return false;
        }
    }
    if (!ApplyStep(row, "NT-LAN-007", "wan", static_cast<int64_t>(1), true, false, "UNCHANGED", err)) return false;
    err.clear();
    return true;
}

bool Jrn10::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn10::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn10::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Jrn10::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn10::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
