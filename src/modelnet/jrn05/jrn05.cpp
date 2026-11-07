// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn05/jrn05.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/acc05/acc05.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct Refusal {
    const char* id;
    const char* text;
    int64_t aux;
    bool flag;
    const char* err;
};

struct KnownRow {
    const char* id;
    const char* text;
    const char* again;
    const char* refuse;
    const char* refuse_err;
};

// Refusal fixtures copied from acc05_tests. None of these store.
const Refusal kRefuse[] = {
    {"WAN-002", "", static_cast<int64_t>(-1), false, "FIELD"},
    {"WAN-002", "staged", static_cast<int64_t>(-1), true, "BOUND"},
    {"WAN-002", "staged", static_cast<int64_t>(101), false, "CAP"},
    {"WAN-002", "staged", static_cast<int64_t>(0), false, "ABSENT"},

    {"WAN-004", "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "fp4", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "dualpipe", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "vllm", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "sglang", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "lmcache", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "nixl", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "mooncake", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "rdma", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "deepinfer", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "dualpipe", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-004", "fp4", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"WAN-002", "vllm", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},

    {"WAN-004", "private trajectory", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA},
    {"API-001", "private-idempotency", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA},

    {"WAN-002", "other-state", static_cast<int64_t>(1), true, "STATE"},
    {"WAN-003", "mixed", static_cast<int64_t>(1), true, "GENERATION"},
    {"WAN-003", "mixed", static_cast<int64_t>(1), true, "GENERATION"},
    {"WAN-005", "symlink", static_cast<int64_t>(1), true, "TAR"},
    {"ENT-001", "rpc", static_cast<int64_t>(1), true, "ROUTE"},
    {"ENT-003", "endorse", static_cast<int64_t>(1), true, "REVIEW"},
    {"ECON-001", "spend", static_cast<int64_t>(1), true, "WALLET"},
    {"STORE-002", "retry", static_cast<int64_t>(1), true, "UNKNOWN"},
    {"STORE-003", "skip-sig", static_cast<int64_t>(1), true, "LIMIT"},
    {"API-001", "s1", static_cast<int64_t>(1), true, "IDEMPOTENT"},
    {"API-003", "other", static_cast<int64_t>(1), true, "CLI"},
    {"API-003", "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"API-004", "trusted", static_cast<int64_t>(1), true, "BADGE"},
};

// Admission arguments copied from acc05_tests kKnown.
const KnownRow kKnown[] = {
    {"WAN-002", "staged", "active", "other-state", "STATE"},
    {"WAN-003", "single", "uniform", "mixed", "GENERATION"},
    {"WAN-004", "noted", "other-sentence", nullptr, nullptr},
    {"WAN-005", "archive", "packed", "symlink", "TAR"},
    {"ENT-001", "local", "member-path", "rpc", "ROUTE"},
    {"ENT-002", "member", "seat", nullptr, nullptr},
    {"ENT-003", "review-held", "noted", "endorse", "REVIEW"},
    {"ECON-001", "quote", "meter", "spend", "WALLET"},
    {"ECON-002", "meter", "quote", nullptr, nullptr},
    {"STORE-001", "object", "blob", nullptr, nullptr},
    {"STORE-002", "once", "later", "retry", "UNKNOWN"},
    {"STORE-003", "signed", "sealed", "skip-sig", "LIMIT"},
    {"API-001", "idempotency-s1", "idempotency-s2", "s1", "IDEMPOTENT"},
    {"API-002", "route-s1", "route-s2", nullptr, nullptr},
    {"API-003", "research", "model", "other", "CLI"},
    {"API-004", "shown", "plain", "trusted", "BADGE"},
};

bool ContinueRefusal(Acc05& acc, const char* id, const char* text, int64_t aux, bool flag, const char* want, std::string& err)
{
    if (acc.Apply(id, text, aux, flag, err)) return false;
    return err == want;
}

} // namespace

bool Jrn05::Pass(std::string& err)
{
    Acc05 acc;
    for (const Refusal& step : kRefuse) {
        if (!ContinueRefusal(acc, step.id, step.text, step.aux, step.flag, step.err, err)) return false;
    }
    for (const KnownRow& row : kKnown) {
        if (row.refuse != nullptr) {
            if (!ContinueRefusal(acc, row.id, row.refuse, static_cast<int64_t>(1), true, row.refuse_err, err)) return false;
        }
        if (!acc.Apply(row.id, row.text, static_cast<int64_t>(1), true, err) || !err.empty()) return false;
        if (!ContinueRefusal(acc, row.id, row.text, static_cast<int64_t>(1), true, NIFDT_REPLAY, err)) return false;
        if (!ContinueRefusal(acc, row.id, row.again, static_cast<int64_t>(1), true, "UNCHANGED", err)) return false;
        if (row.refuse != nullptr) {
            if (!ContinueRefusal(acc, row.id, row.refuse, static_cast<int64_t>(1), true, row.refuse_err, err)) return false;
        }
    }
    err.clear();
    return true;
}

bool Jrn05::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn05::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn05::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn05::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn05::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
