// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv13/liv13.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp13/grp13.h>

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
    {"ASR-HND-001", "", "beta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GRANT"},
    {"ASR-HND-001", "", "beta", "alpha", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-HND-001", "", "beta", "gamma", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-HND-002", "", "fence-ok", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FENCE"},
    {"ASR-HND-002", "", "fence-ok", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"ASR-HND-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"ASR-HND-003", "", "cross", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "AMBIGUOUS"},
    {"ASR-HND-003", "", "crossroad", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "AMBIGUOUS"},
    {"ASR-HND-003", "", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-HND-003", "", "cross", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "AMBIGUOUS"},
    {"ASR-HND-003", "", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-HND-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "USEFUL"},
    {"ASR-HND-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"ASR-HND-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"ASR-KVC-001", "", "a,b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "INCOMPATIBLE"},
    {"ASR-KVC-001", "", "a,b,c,d,e", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "INCOMPATIBLE"},
    {"ASR-KVC-001", "", "a,b,c,d", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-KVC-001", "", "w,x,y,z", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-KVC-002", "", "pre", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "SUFFIX"},
    {"ASR-KVC-002", "", "pre", "suf", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"ASR-KVC-002", "", "pre", "suf", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "REPLAY"},
    {"ASR-KVC-002", "", "pre2", "suf", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "STALE"},
    {"ASR-KVC-002", "", "pre2", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "SUFFIX"},
    {"ASR-KVC-002", "", "pre", "suf", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "REPLAY"},
    {"ASR-KVC-003", "", "ni" "xl", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "ENGINE_ABSENT"},
    {"ASR-KVC-003", "", "moon" "cake", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "ENGINE_ABSENT"},
    {"ASR-KVC-003", "", "rd" "ma", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "ENGINE_ABSENT"},
    {"ASR-KVC-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BOUND"},
    {"ASR-KVC-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(12), false, true, ""},
    {"ASR-KVC-003", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "REPLAY"},
    {"ASR-KVC-003", "", "ni" "xl", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "ENGINE_ABSENT"},
    {"ASR-KVC-004", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HASH"},
    {"ASR-KVC-004", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"ASR-KVC-004", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HASH"},
    {"ASR-KVC-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BOUND"},
    {"ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "BOUND"},
    {"ASR-KVC-005", "revoke", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "BOUND"},
    {"ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, true, ""},
    {"ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, false, "REPLAY"},
    {"ASR-KVC-005", "revoke", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, true, ""},
    {"ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BOUND"},
    {"ASR-KVC-005", "prefetch", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "REVOKED"},
    {"ASR-KVC-005", "revoke", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "REPLAY"},
    {"ASR-KVC-006", "", "measured", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNMEASURED"},
    {"ASR-KVC-006", "", "measured", "x", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-KVC-006", "", "other", "y", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-MIG-001", "", "skip", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "ASSURANCE"},
    {"ASR-MIG-001", "", "kept", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-MIG-001", "", "skip", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "ASSURANCE"},
    {"ASR-MIG-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-MIG-002", "", "page", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "JOURNAL"},
    {"ASR-MIG-002", "", "page", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"ASR-MIG-002", "", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "JOURNAL"},
    {"ASR-MIG-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"ASR-NAT-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "OWNER"},
    {"ASR-NAT-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "OWNER"},
    {"ASR-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "SPAWN"},
    {"ASR-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-NAT-002", "mark", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(11), false, true, ""},
    {"ASR-NAT-002", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(99), false, true, ""},
    {"ASR-NAT-002", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "REPLAY"},
    {"ASR-NAT-002", "mark", "row", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "REPLAY"},
    {"ASR-NAT-003", "", "zero", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "BOUND"},
    {"ASR-NAT-003", "", "zero", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-NAT-003", "", "five", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, false, "REPLAY"},
    {"ASR-NAT-004", "", "wallet", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "WALLET"},
    {"ASR-NAT-004", "", "disk", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "RESOURCE"},
    {"ASR-NAT-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "RESOURCE"},
    {"ASR-NAT-004", "", "cpu", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-NAT-004", "", "memory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
};

} // namespace

bool Liv13::Pass(std::string& err)
{
    Grp13 group;
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

bool Liv13::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv13::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv13::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv13::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv13::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
