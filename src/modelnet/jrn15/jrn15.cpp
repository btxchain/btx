// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn15/jrn15.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/dtat04/dtat04.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kIds[] = {
    "DT-AT-RLP-001",
    "DT-AT-RLP-002",
    "DT-AT-RLP-003",
    "DT-AT-RLP-004",
    "DT-AT-RLP-005",
    "DT-AT-RLP-006",
    "DT-AT-RLP-007",
    "DT-AT-RLP-008",
    "DT-AT-CKP-001",
    "DT-AT-CKP-002",
    "DT-AT-CKP-003",
    "DT-AT-CKP-004",
    "DT-AT-CKP-005",
    "DT-AT-CKP-006",
    "DT-AT-CKP-007",
    "DT-AT-CKP-008",
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

bool Same(Dtat04& eng, const std::string& id, const std::string& text, int64_t aux, bool flag, bool accept, const char* want, std::string& err)
{
    const bool ok = eng.Apply(id, text, aux, flag, err);
    if (!accept) {
        if (ok || err != want) return false;
    } else if (!ok || !err.empty()) {
        return false;
    }
    return eng.scenario_status() == "NOT_RUN";
}

bool Refusals(Dtat04& eng, std::string& err)
{
    if (!Same(eng, "", "", static_cast<int64_t>(-1), false, false, "ID", err)) return false;
    if (!Same(eng, "DT-NO-SUCH", "s1", static_cast<int64_t>(1), true, false, "ID", err)) return false;
    if (!Same(eng, "DT-AT-RLP-009", "s1", static_cast<int64_t>(1), true, false, "ID", err)) return false;
    if (!Same(eng, "DT-AT-CKP-009", "pickle", static_cast<int64_t>(1), true, false, "ID", err)) return false;
    if (!Same(eng, "DT-AT-RLP-001", "", static_cast<int64_t>(-1), false, false, "FIELD", err)) return false;
    if (!Same(eng, "DT-AT-RLP-001", "s1", static_cast<int64_t>(-1), true, false, "BOUND", err)) return false;
    if (!Same(eng, "DT-AT-RLP-001", "s1", static_cast<int64_t>(101), false, false, "CAP", err)) return false;
    if (!Same(eng, "DT-AT-RLP-001", "s1", static_cast<int64_t>(0), false, false, "ABSENT", err)) return false;
    if (!Same(eng, "DT-AT-RLP-006", "", static_cast<int64_t>(1), false, false, "FIELD", err)) return false;
    if (!Same(eng, "DT-AT-RLP-006", "s1", static_cast<int64_t>(-1), false, false, "BOUND", err)) return false;
    if (!Same(eng, "DT-AT-RLP-006", "s1", static_cast<int64_t>(101), false, false, "CAP", err)) return false;
    if (!Same(eng, "DT-AT-RLP-006", "s1", static_cast<int64_t>(1), false, false, "ROUTE", err)) return false;

    for (const char* name : kEngines) {
        if (!Same(eng, "DT-AT-RLP-001", name, static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
    }
    if (!Same(eng, "DT-AT-RLP-006", "vllm", static_cast<int64_t>(1), false, false, "ROUTE", err)) return false;
    if (!Same(eng, "DT-AT-RLP-006", "pickle", static_cast<int64_t>(1), false, false, "ROUTE", err)) return false;

    if (!Same(eng, "DT-AT-CKP-004", "vllm", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
    if (!Same(eng, "DT-AT-CKP-004", "pickle", static_cast<int64_t>(1), true, false, "CODE", err)) return false;
    if (!Same(eng, "DT-AT-CKP-004", "private note", static_cast<int64_t>(1), true, false, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Same(eng, "DT-AT-CKP-004", "s1", static_cast<int64_t>(1), false, false, "ABSENT", err)) return false;
    if (!Same(eng, "DT-AT-CKP-004", "s1", static_cast<int64_t>(0), true, false, NIFDT_UNQUALIFIED, err)) return false;
    if (!Same(eng, "DT-AT-CKP-004", "s1", static_cast<int64_t>(100), true, false, NIFDT_UNQUALIFIED, err)) return false;

    if (!Same(eng, "DT-AT-RLP-003", "pickle", static_cast<int64_t>(1), true, false, "CODE", err)) return false;
    if (!Same(eng, "DT-AT-RLP-003", "has pickle", static_cast<int64_t>(1), true, false, "CODE", err)) return false;
    if (!Same(eng, "DT-AT-RLP-003", "private pickle", static_cast<int64_t>(1), true, false, "CODE", err)) return false;
    if (!Same(eng, "DT-AT-RLP-003", "private", static_cast<int64_t>(1), true, false, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Same(eng, "DT-AT-RLP-003", "s1 private", static_cast<int64_t>(1), true, false, NIFDT_PRIVATE_DATA, err)) return false;
    return true;
}

bool EveryId(Dtat04& eng, std::string& err)
{
    for (const char* id : kIds) {
        if (std::string(id) == "DT-AT-CKP-004") {
            if (!Same(eng, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_UNQUALIFIED, err)) return false;
            if (!Same(eng, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_UNQUALIFIED, err)) return false;
            if (!Same(eng, id, "s2", static_cast<int64_t>(100), true, false, NIFDT_UNQUALIFIED, err)) return false;
            continue;
        }
        if (std::string(id) == "DT-AT-RLP-006") {
            if (!Same(eng, id, "s1", static_cast<int64_t>(1), false, false, "ROUTE", err)) return false;
        }
        if (!Same(eng, id, "s1", static_cast<int64_t>(1), true, true, "", err)) return false;
        if (!Same(eng, id, "s1", static_cast<int64_t>(1), true, false, NIFDT_REPLAY, err)) return false;
        if (!Same(eng, id, "s2", static_cast<int64_t>(1), true, false, "UNCHANGED", err)) return false;
    }
    if (!Same(eng, "DT-AT-RLP-006", "s1", static_cast<int64_t>(1), false, false, "ROUTE", err)) return false;
    if (!Same(eng, "DT-AT-RLP-003", "fp4", static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT, err)) return false;
    if (!Same(eng, "DT-AT-RLP-003", "has pickle", static_cast<int64_t>(1), true, false, "CODE", err)) return false;
    if (!Same(eng, "DT-AT-RLP-003", "private note", static_cast<int64_t>(1), true, false, NIFDT_PRIVATE_DATA, err)) return false;
    return true;
}

} // namespace

bool Jrn15::Pass(std::string& err)
{
    Dtat04 eng;
    if (!Refusals(eng, err)) return false;
    if (!EveryId(eng, err)) return false;
    if (eng.scenario_status() != "NOT_RUN") return false;
    if (eng.launched() || eng.gpu() || eng.broadcast() || eng.qualified() || eng.release_qualified() || eng.hardware_qualified()) return false;
    if (eng.hosts() != static_cast<int64_t>(1)) return false;
    if (eng.physical_hosts() != static_cast<int64_t>(1)) return false;
    if (eng.bytes_moved() != static_cast<int64_t>(0)) return false;
    if (eng.automatic_spend() != NIFDT_AUTOMATIC_SPEND) return false;
    err.clear();
    return true;
}

bool Jrn15::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn15::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn15::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn15::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn15::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
