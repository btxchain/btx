// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv12/liv12.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp12/grp12.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct Call {
    const char* id;
    const char* op;
    const char* text;
    const char* extra;
    int64_t now_ms;
    int64_t aux;
    bool flag;
    bool accept;
    const char* want;
};

const Call kCalls[] = {
    {"ASR-EVO-001", "", "delta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNVERIFIED"},
    {"ASR-EVO-001", "", "delta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"ASR-EVO-001", "", "delta", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"ASR-EVO-001", "", "delta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNVERIFIED"},
    {"ASR-EVO-002", "", "pop", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "NICHE"},
    {"ASR-EVO-002", "", "pop", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "NICHE"},
    {"ASR-EVO-002", "", "pop", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, true, ""},
    {"ASR-EVO-002", "", "pop", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "REPLAY"},
    {"ASR-EVO-002", "", "wide", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"ASR-EVO-003", "", "policy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BASELINE"},
    {"ASR-EVO-003", "", "policy", "base", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-EVO-003", "", "policy", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-EVO-004", "promote", "policy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED"},
    {"ASR-EVO-004", "shadow", "policy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-EVO-004", "promote", "policy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "UNQUALIFIED"},
    {"ASR-EVO-004", "shadow", "policy", "again", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-EXE-001", "", "", "attempt", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SEPARATE"},
    {"ASR-EXE-001", "", "intent", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SEPARATE"},
    {"ASR-EXE-001", "", "intent", "attempt", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-EXE-001", "", "intent", "later", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-EXE-002", "", "one", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-EXE-002", "", "one", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-EXE-002", "other", "one", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-EXE-002", "", "two", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ALTERED"},
    {"ASR-EXE-003", "", "once", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNKNOWN"},
    {"ASR-EXE-003", "", "once", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"ASR-EXE-003", "", "once", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"ASR-EXE-003", "", "once", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNKNOWN"},
    {"ASR-EXE-004", "", "lease", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FENCE"},
    {"ASR-EXE-004", "", "lease", "token", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-EXE-004", "", "lease", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-EXE-005", "", "lease", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, false, "EXPIRED"},
    {"ASR-EXE-005", "", "lease", "", static_cast<int64_t>(6), static_cast<int64_t>(5), false, false, "EXPIRED"},
    {"ASR-EXE-005", "", "lease", "", static_cast<int64_t>(4), static_cast<int64_t>(5), false, true, ""},
    {"ASR-EXE-005", "", "lease", "", static_cast<int64_t>(4), static_cast<int64_t>(9), false, false, "REPLAY"},
    {"ASR-EXE-005", "", "lease", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, false, "EXPIRED"},
    {"ASR-EXE-006", "", "seat", "compatible", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REVOKED"},
    {"ASR-EXE-006", "", "seat", "compatible", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-EXE-006", "", "seat", "compatible", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-EXE-006", "", "seat", "compatible", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REVOKED"},
    {"ASR-EXE-007", "", "hold", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, true, ""},
    {"ASR-EXE-007", "", "hold", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "REPLAY"},
    {"ASR-EXE-007", "later", "wake", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "UNCHANGED"},
    {"ASR-EXE-007", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "UNCHANGED"},
    {"ASR-GRF-001", "", "loss", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "VIEW"},
    {"ASR-GRF-001", "", "dependency", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-GRF-001", "alt", "dependency", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-GRF-001", "", "evidence", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-GRF-001", "", "payment", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-GRF-001", "", "resource", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-GRF-001", "", "evidence", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-GRF-002", "", "loop", "loop", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CYCLE"},
    {"ASR-GRF-002", "", "edge", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-GRF-002", "", "edge", "later", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-GRF-002", "", "loop", "loop", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CYCLE"},
    {"ASR-GRF-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-GRF-003", "", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-GRF-003", "", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "REPLAY"},
    {"ASR-GRF-003", "retract", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-GRF-003", "retract", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-GRF-003", "retract", "hist", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, true, ""},
    {"ASR-GRF-003", "retract", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"ASR-GRF-003", "retract", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "REPLAY"},
    {"ASR-GRF-004", "rank", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "ORDER"},
    {"ASR-GRF-004", "score", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "ORDER"},
    {"ASR-GRF-004", "filter", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, true, ""},
    {"ASR-GRF-004", "filter", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "REPLAY"},
    {"ASR-GRF-004", "rank", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, true, ""},
    {"ASR-GRF-004", "rank", "top", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "REPLAY"},
    {"ASR-GRF-005", "", "scope", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, false, "BOUND"},
    {"ASR-GRF-005", "", "scope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BOUND"},
    {"ASR-GRF-005", "", "scope", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"ASR-GRF-005", "", "scope", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "REPLAY"},
    {"ASR-GRF-005", "", "low", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, true, ""},
};

} // namespace

bool Liv12::Pass(std::string& err)
{
    Grp12 group;
    for (const Call& call : kCalls) {
        const bool ok = group.Apply(call.id, call.op, call.text, call.extra, call.now_ms, call.aux, call.flag, err);
        if (!call.accept) {
            if (ok) {
                err = "STEP";
                return false;
            }
            if (err != call.want) return false;
            continue;
        }
        if (!ok || !err.empty()) return false;
    }
    err.clear();
    return true;
}

bool Liv12::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv12::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv12::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv12::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv12::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
