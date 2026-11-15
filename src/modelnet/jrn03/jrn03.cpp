// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn03/jrn03.h>
#include <modelnet/acc03/acc03.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct KnownRow {
    const char* id;
    const char* text;
    const char* again;
    const char* blocked;
    const char* blocked_err;
};

const KnownRow kKnown[] = {
    {"SCM-003", "bounded-fetch", "other-sentence", "fetch-all", "PREFETCH"},
    {"SCM-004", "closed-set", "other-sentence", nullptr, nullptr},
    {"RES-001", "observe", "other-sentence", "assign", "AUTHORITY"},
    {"RES-002", "local-note", "other-sentence", nullptr, nullptr},
    {"RES-003", "LEADING", "CONTESTED", "other-view", "VIEW"},
    {"RES-004", "closed-grammar", "other-sentence", "parser", "PARSER"},
    {"RES-005", "local-note", "other-sentence", nullptr, nullptr},
    {"ART-001", "frozen-label", "other-sentence", "tag", "MUTABLE"},
    {"ART-002", "local-note", "other-sentence", nullptr, nullptr},
    {"ART-003", "local-note", "other-sentence", nullptr, nullptr},
    {"VER-001", "local-check", "other-sentence", "network", "FETCH"},
    {"VER-002", "rng-s1", "rng-other", "plain", "STATE"},
    {"VER-003", "held-out", "other-sentence", "sample", "GAP"},
    {"VER-004", "other-check", "other-sentence", "self", "SELF"},
    {"ADM-001", "named-set", "other-sentence", "one-root", "QUORUM"},
    {"ADM-002", "hostmodel", "importmodel", "not-a-path", "PATH"},
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

bool Step(Acc03& acc, const char* id, const char* text, int64_t aux, bool flag, const char* refused, std::string& err)
{
    const bool ok = acc.Apply(id, text, aux, flag, err);
    if (refused != nullptr) {
        return !ok && err == refused;
    }
    return ok;
}

} // namespace

bool Jrn03::Pass(std::string& err)
{
    Acc03 acc;
    const int64_t one = static_cast<int64_t>(1);

    if (!Step(acc, "SCM-003", "", static_cast<int64_t>(-1), false, "FIELD", err)) return false;
    if (!Step(acc, "SCM-003", "bounded-fetch", static_cast<int64_t>(-1), true, "BOUND", err)) return false;
    if (!Step(acc, "SCM-003", "bounded-fetch", static_cast<int64_t>(101), false, "CAP", err)) return false;
    if (!Step(acc, "SCM-003", "bounded-fetch", static_cast<int64_t>(0), false, "ABSENT", err)) return false;

    for (const char* name : kEngines) {
        if (!Step(acc, "SCM-004", name, one, true, NIFDT_ENGINE_ABSENT, err)) return false;
    }
    if (!Step(acc, "SCM-004", "private trajectory", one, true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Step(acc, "SCM-003", "vllm", one, true, NIFDT_ENGINE_ABSENT, err)) return false;
    if (!Step(acc, "SCM-003", "private fetch-all", one, true, NIFDT_PRIVATE_DATA, err)) return false;

    if (!Step(acc, "SCM-003", "fetch-all", one, false, "ABSENT", err)) return false;
    if (!Step(acc, "SCM-003", "fetch-all", one, true, "PREFETCH", err)) return false;
    if (!Step(acc, "SCM-003", "fetch-all", one, true, "PREFETCH", err)) return false;
    if (!Step(acc, "RES-001", "assign", one, true, "AUTHORITY", err)) return false;
    if (!Step(acc, "RES-003", "recent", one, true, "VIEW", err)) return false;
    if (!Step(acc, "RES-004", "parser", one, true, "PARSER", err)) return false;
    if (!Step(acc, "ART-001", "tag", one, true, "MUTABLE", err)) return false;
    if (!Step(acc, "VER-001", "network", one, true, "FETCH", err)) return false;
    if (!Step(acc, "VER-002", "plain", one, true, "STATE", err)) return false;
    if (!Step(acc, "VER-002", "RNG-s1", one, true, "STATE", err)) return false;
    if (!Step(acc, "VER-002", "fp4", one, true, NIFDT_ENGINE_ABSENT, err)) return false;
    if (!Step(acc, "VER-002", "private-rng", one, true, NIFDT_PRIVATE_DATA, err)) return false;
    if (!Step(acc, "VER-003", "sample", one, true, "GAP", err)) return false;
    if (!Step(acc, "VER-004", "self", one, true, "SELF", err)) return false;
    if (!Step(acc, "ADM-001", "one-root", one, true, "QUORUM", err)) return false;
    if (!Step(acc, "ADM-002", "fp8", one, true, NIFDT_ENGINE_ABSENT, err)) return false;
    if (!Step(acc, "ADM-002", "not-a-path", one, true, "PATH", err)) return false;

    for (const KnownRow& row : kKnown) {
        if (row.blocked != nullptr) {
            if (!Step(acc, row.id, row.blocked, one, true, row.blocked_err, err)) return false;
        }
        if (!Step(acc, row.id, row.text, one, true, nullptr, err)) return false;
        if (!Step(acc, row.id, row.text, one, true, NIFDT_REPLAY, err)) return false;
        if (!Step(acc, row.id, row.again, one, true, "UNCHANGED", err)) return false;
    }

    if (!Step(acc, "VER-002", "has-rng-inside", one, true, "UNCHANGED", err)) return false;
    if (!Step(acc, "VER-002", "plain", one, true, "STATE", err)) return false;
    if (!Step(acc, "SCM-004", "dualpipev", one, true, "UNCHANGED", err)) return false;
    if (!Step(acc, "ADM-002", "not-a-path", one, true, "PATH", err)) return false;

    err.clear();
    return true;
}

bool Jrn03::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn03::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn03::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn03::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn03::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
