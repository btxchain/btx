// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn06/jrn06.h>
#include <modelnet/acc06/acc06.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct KnownRow {
    const char* id;
    const char* refusal;
    const char* code;
};

const KnownRow kKnown[] = {
    {"MIG-001", "wallet", "UNTOUCHED"},
    {"MIG-002", "fabricate", "LEGACY"},
    {"MIG-003", "downgrade", "PROTOCOL"},
    {"BUILD-001", nullptr, nullptr},
    {"BUILD-002", "windows", "UNQUALIFIED"},
    {"BUILD-003", "skip", "MEASURE"},
    {"INC-001", "blocklist", "SCOPE"},
    {"INC-002", "self", "RUNBOOK"},
    {"DEV-001", nullptr, nullptr},
    {"DEV-002", "grep", "EVIDENCE"},
    {"DEV-003", "doc", "JOURNEY"},
    {"E2E-001", "assign", "AUTHORITY"},
    {"E2E-002", "altered", "MISMATCH"},
    {"E2E-003", "hook", "SAFE"},
    {"E2E-004", "one-attestor", "QUORUM"},
    {"E2E-005", "shrink", "THRESHOLD"},
};

const char* const kRemote[] = {
    "vllm",
    "sglang",
    "lmcache",
    "nixl",
    "mooncake",
    "rdma",
    "deepinfer",
    "dualpipe",
};

bool Run(Acc06& acc, const char* id, const char* text, int64_t aux, bool flag, const char* expect, std::string& err)
{
    const bool ok = acc.Apply(id, text, aux, flag, err);
    if (expect == nullptr) return ok && err.empty();
    if (ok) return false;
    return err == expect;
}

} // namespace

bool Jrn06::Pass(std::string& err)
{
    Acc06 acc;

    if (!Run(acc, "MIG-001", "", static_cast<int64_t>(-1), false, "FIELD", err)) return false;
    if (!Run(acc, "MIG-001", "s1", static_cast<int64_t>(-1), true, "BOUND", err)) return false;
    if (!Run(acc, "MIG-001", "s1", static_cast<int64_t>(101), false, "CAP", err)) return false;
    if (!Run(acc, "MIG-001", "s1", static_cast<int64_t>(0), false, "ABSENT", err)) return false;
    if (!Run(acc, "BUILD-002", "windows", static_cast<int64_t>(-1), true, "BOUND", err)) return false;
    if (!Run(acc, "BUILD-002", "windows", static_cast<int64_t>(1), false, "ABSENT", err)) return false;

    if (!Run(acc, "BUILD-001", "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
    if (!Run(acc, "BUILD-001", "fp4", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
    if (!Run(acc, "BUILD-001", "dualpipe", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
    for (const char* name : kRemote) {
        if (!Run(acc, "BUILD-001", name, static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
    }

    if (!Run(acc, "MIG-001", "private trajectory", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Run(acc, "MIG-001", "private wallet", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Run(acc, "MIG-001", "wallet", static_cast<int64_t>(1), true, "UNTOUCHED", err)) return false;
    if (!Run(acc, "MIG-002", "fabricate", static_cast<int64_t>(1), true, "LEGACY", err)) return false;
    if (!Run(acc, "MIG-003", "downgrade", static_cast<int64_t>(1), true, "PROTOCOL", err)) return false;
    if (!Run(acc, "BUILD-002", "windows", static_cast<int64_t>(1), true, NIFDT_UNQUALIFIED, err)) return false;
    if (!Run(acc, "BUILD-002", "macos", static_cast<int64_t>(1), true, NIFDT_UNQUALIFIED, err)) return false;
    if (!Run(acc, "BUILD-003", "skip", static_cast<int64_t>(1), true, "MEASURE", err)) return false;
    if (!Run(acc, "INC-001", "blocklist", static_cast<int64_t>(1), true, "SCOPE", err)) return false;
    if (!Run(acc, "INC-002", "self", static_cast<int64_t>(1), true, "RUNBOOK", err)) return false;
    if (!Run(acc, "DEV-002", "grep", static_cast<int64_t>(1), true, "EVIDENCE", err)) return false;
    if (!Run(acc, "DEV-003", "doc", static_cast<int64_t>(1), true, "JOURNEY", err)) return false;
    if (!Run(acc, "E2E-001", "assign", static_cast<int64_t>(1), true, "AUTHORITY", err)) return false;
    if (!Run(acc, "E2E-002", "altered", static_cast<int64_t>(1), true, "MISMATCH", err)) return false;
    if (!Run(acc, "E2E-003", "hook", static_cast<int64_t>(1), true, "SAFE", err)) return false;
    if (!Run(acc, "E2E-004", "one-attestor", static_cast<int64_t>(1), true, "QUORUM", err)) return false;
    if (!Run(acc, "E2E-005", "shrink", static_cast<int64_t>(1), true, "THRESHOLD", err)) return false;

    for (const KnownRow& row : kKnown) {
        if (row.refusal != nullptr) {
            const char* expect = row.code;
            if (std::string(row.id) == "BUILD-002") expect = NIFDT_UNQUALIFIED;
            if (!Run(acc, row.id, row.refusal, static_cast<int64_t>(1), true, expect, err)) return false;
        }
        if (std::string(row.id) == "BUILD-002") {
            if (!Run(acc, row.id, "macos", static_cast<int64_t>(1), true, NIFDT_UNQUALIFIED, err)) return false;
        }
        if (!Run(acc, row.id, "s1", static_cast<int64_t>(1), true, nullptr, err)) return false;
        if (!Run(acc, row.id, "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY, err)) return false;
        if (!Run(acc, row.id, "s2", static_cast<int64_t>(1), true, "UNCHANGED", err)) return false;
    }

    if (!Run(acc, "BUILD-002", "windows", static_cast<int64_t>(1), true, NIFDT_UNQUALIFIED, err)) return false;
    if (!Run(acc, "MIG-001", "wallet", static_cast<int64_t>(1), true, "UNTOUCHED", err)) return false;
    if (!Run(acc, "DEV-001", "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
    if (!Run(acc, "DEV-001", "private trajectory", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA, err)) return false;

    err.clear();
    return true;
}

bool Jrn06::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn06::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn06::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn06::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn06::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
