// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn01/jrn01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/acc01/acc01.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct KnownRow {
    const char* id;
    const char* text;
    const char* other;
    int64_t aux;
};

const KnownRow kKnown[] = {
    {"CORE-001", "s1", "s2", static_cast<int64_t>(0)},
    {"CORE-002", "s1", "s2", static_cast<int64_t>(100)},
    {"CORE-003", "s1", "s2", static_cast<int64_t>(1)},
    {"CORE-004", "s1", "s2", static_cast<int64_t>(1)},
    {"CORE-005", "s1", "s2", static_cast<int64_t>(1)},
    {"ARCH-001", "s1", "s2", static_cast<int64_t>(1)},
    {"ARCH-002", "s1", "s2", static_cast<int64_t>(1)},
    {"ARCH-003", "s1", "s2", static_cast<int64_t>(1)},
    {"ARCH-004", "public_participant", "community_realm", static_cast<int64_t>(1)},
    {"SEC-001", "s1", "s2", static_cast<int64_t>(1)},
    {"SEC-002", "s1", "s2", static_cast<int64_t>(1)},
    {"SEC-003", "s1", "s2", static_cast<int64_t>(1)},
    {"SEC-004", "s1", "s2", static_cast<int64_t>(1)},
    {"WIRE-001", "s1-1.1.0", "s2-1.1.0", static_cast<int64_t>(1)},
    {"WIRE-002", "s1", "s2", static_cast<int64_t>(1)},
    {"WIRE-003", "s1", "s2", static_cast<int64_t>(1)},
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

bool Step(Acc01& acc, const char* id, const char* text, int64_t aux, bool flag, const char* refused, std::string& err)
{
    const bool ok = acc.Apply(id, text, aux, flag, err);
    if (refused != nullptr) {
        return !ok && err == refused;
    }
    return ok && err.empty();
}

} // namespace

bool Jrn01::Pass(std::string& err)
{
    Acc01 acc;
    const int64_t one = static_cast<int64_t>(1);

    if (!Step(acc, "", "", static_cast<int64_t>(0), true, "ID", err)) return false;
    if (!Step(acc, "NO-SUCH", "s1", one, true, "ID", err)) return false;
    if (!Step(acc, "CORE-006", "s1", one, true, "ID", err)) return false;

    if (!Step(acc, "CORE-001", "", static_cast<int64_t>(-1), false, "FIELD", err)) return false;
    if (!Step(acc, "CORE-001", "s1", static_cast<int64_t>(-1), true, "BOUND", err)) return false;
    if (!Step(acc, "CORE-001", "s1", static_cast<int64_t>(101), false, "CAP", err)) return false;
    if (!Step(acc, "CORE-001", "s1", static_cast<int64_t>(0), false, "ABSENT", err)) return false;

    for (const char* name : kEngines) {
        if (!Step(acc, "CORE-001", name, one, true, NIFDT_ENGINE_ABSENT, err)) return false;
    }

    if (!Step(acc, "CORE-001", "private note", one, true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Step(acc, "CORE-001", "private_personal", one, true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Step(acc, "CORE-003", "private consensus", one, true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Step(acc, "CORE-003", "has consensus", one, true, "CONSENSUS", err)) return false;
    if (!Step(acc, "CORE-005", "a claim", one, true, "CLAIM", err)) return false;
    if (!Step(acc, "ARCH-001", "hardware", one, true, NIFDT_UNQUALIFIED, err)) return false;
    if (!Step(acc, "ARCH-002", "assign", one, true, "AUTHORITY", err)) return false;
    if (!Step(acc, "ARCH-004", "s1", one, true, "PROFILE", err)) return false;
    if (!Step(acc, "ARCH-004", "private note", one, true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Step(acc, "SEC-002", "shell", one, true, "QUARANTINE", err)) return false;
    if (!Step(acc, "WIRE-001", "s1", one, true, "VERSION", err)) return false;
    if (!Step(acc, "WIRE-003", "oversize", one, true, "LIMIT", err)) return false;

    for (const KnownRow& row : kKnown) {
        if (!Step(acc, row.id, row.text, row.aux, true, nullptr, err)) return false;
        if (!Step(acc, row.id, row.text, one, true, NIFDT_REPLAY, err)) return false;
        if (!Step(acc, row.id, row.other, one, true, "UNCHANGED", err)) return false;
    }

    if (acc.release_qualified() || acc.qualified() || acc.hardware_qualified()) return false;
    if (acc.launched() || acc.gpu() || acc.broadcast()) return false;
    if (acc.hosts() != static_cast<int64_t>(1)) return false;
    if (acc.physical_hosts() != static_cast<int64_t>(1)) return false;
    if (acc.bytes_moved() != static_cast<int64_t>(0)) return false;

    err.clear();
    return true;
}

bool Jrn01::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Jrn01::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn01::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
