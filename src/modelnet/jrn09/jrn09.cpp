// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn09/jrn09.h>
#include <modelnet/nt02/nt02.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "NT-EXEC-001",
    "NT-EXEC-002",
    "NT-EXEC-003",
    "NT-EXEC-004",
    "NT-EXEC-005",
    "NT-EXEC-006",
    "NT-KV-001",
    "NT-KV-002",
    "NT-KV-003",
    "NT-KV-004",
    "NT-KV-005",
    "NT-KV-006",
    "NT-KV-007",
    "NT-KV-008",
    "NT-LAN-001",
    "NT-LAN-002",
    "NT-LAN-003",
    "NT-LAN-004",
};

bool KvAbsent(const char* id)
{
    return std::string(id) == "NT-KV-004" || std::string(id) == "NT-KV-007";
}

bool ApplyStep(Nt02& row, const char* id, const char* text, int64_t aux, bool flag,
               bool expect_ok, const char* expect_err, std::string& err)
{
    const bool ok = row.Apply(id, text, aux, flag, err);
    if (row.scenario_status() != "NOT_RUN") return false;
    if (expect_ok) return ok && err.empty();
    if (ok || expect_err == nullptr || err != expect_err) return false;
    return true;
}

} // namespace

bool Jrn09::Pass(std::string& err)
{
    Nt02 row;
    for (const char* id : kIds) {
        if (KvAbsent(id)) {
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
            if (row.stored(id) || !row.text(id).empty()) return false;
            if (row.bytes_moved() != static_cast<int64_t>(0)) return false;
            if (row.scenario_status() != "NOT_RUN") return false;
            continue;
        }
        if (std::string(id) == "NT-LAN-002") {
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, "HINT", err)) return false;
            if (row.stored(id) || !row.text(id).empty()) return false;
            if (row.scenario_status() != "NOT_RUN") return false;
            continue;
        }
        if (std::string(id) == "NT-LAN-001") {
            if (!ApplyStep(row, id, "s1", static_cast<int64_t>(2), true, false, "HOSTS", err)) return false;
            if (row.stored(id)) return false;
            if (row.hosts() != static_cast<int64_t>(1)) return false;
            if (row.physical_hosts() != static_cast<int64_t>(1)) return false;
        }
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, true, nullptr, err)) return false;
        if (!row.stored(id) || row.text(id) != "s1") return false;
        if (!ApplyStep(row, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_REPLAY, err)) return false;
        if (row.text(id) != "s1") return false;
        if (!ApplyStep(row, id, "s2", static_cast<int64_t>(1), true, false, "UNCHANGED", err)) return false;
        if (row.text(id) != "s1") return false;
        if (row.scenario_status() != "NOT_RUN") return false;
    }
    if (!ApplyStep(row, "NT-LAN-003", "s1", static_cast<int64_t>(2), true, false, NIFDT_REPLAY, err)) return false;
    if (row.text("NT-LAN-003") != "s1") return false;
    if (!ApplyStep(row, "NT-LAN-004", "lane", static_cast<int64_t>(0), true, false, "UNCHANGED", err)) return false;
    if (row.text("NT-LAN-004") != "s1") return false;
    if (row.stored("NT-KV-004") || row.stored("NT-KV-007") || row.stored("NT-LAN-002")) return false;
    if (row.hosts() != static_cast<int64_t>(1) || row.physical_hosts() != static_cast<int64_t>(1)) return false;
    if (row.bytes_moved() != static_cast<int64_t>(0)) return false;
    if (row.automatic_spend() != NIFDT_AUTOMATIC_SPEND) return false;
    if (row.scenario_status() != "NOT_RUN") return false;
    err.clear();
    return true;
}

bool Jrn09::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn09::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn09::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Jrn09::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn09::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
