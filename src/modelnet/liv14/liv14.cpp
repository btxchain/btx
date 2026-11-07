// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv14/liv14.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp14/grp14.h>

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
    {"ASR-NAT-005", "", "watcher", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "BUDGET"},
    {"ASR-NAT-005", "", "watcher", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "BUDGET"},
    {"ASR-NAT-005", "", "watcher", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-NAT-005", "", "observer", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, false, "BUDGET"},
    {"ASR-NAT-005", "", "observer", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-NAT-006", "", "pinned", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-NAT-006", "", "pinned", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-NAT-006", "", "open", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "POLICY"},
    {"ASR-NAT-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "POLICY"},
    {"ASR-NET-001", "", "peer", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "NOT_SCAN"},
    {"ASR-NET-001", "", "peer", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "NOT_SCAN"},
    {"ASR-NET-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "NOT_SCAN"},
    {"ASR-NET-002", "", "wan", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, false, "NO_ROUTE"},
    {"ASR-NET-002", "", "fast", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "SCOPE"},
    {"ASR-NET-002", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, true, ""},
    {"ASR-NET-002", "", "wan", "", static_cast<int64_t>(0), static_cast<int64_t>(99), false, false, "NO_ROUTE"},
    {"ASR-NET-002", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "REPLAY"},
    {"ASR-NET-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GRANT"},
    {"ASR-NET-003", "", "", "grant-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-NET-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GRANT"},
    {"ASR-NET-003", "", "", "grant-b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-NET-003", "", "", "grant-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-NET-004", "", "buf", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PINNED"},
    {"ASR-NET-004", "", "buf", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"ASR-NET-004", "", "next", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"ASR-NET-004", "", "buf", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PINNED"},
    {"ASR-NET-005", "", "unbounded", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-NET-005", "", "limited", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-OBS-001", "ready", "gpu", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "STATUS"},
    {"ASR-OBS-001", "qualify", "gpu", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED"},
    {"ASR-OBS-001", "advertise", "gpu", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-OBS-001", "qualify", "nic", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED"},
    {"ASR-OBS-001", "advertise", "nic", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PAY-001", "", "same", "same", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "POOL"},
    {"ASR-PAY-001", "", "a", "b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BYTES"},
    {"ASR-PAY-001", "", "a", "b", static_cast<int64_t>(0), static_cast<int64_t>(-2), false, false, "BYTES"},
    {"ASR-PAY-001", "", "lane", "other", static_cast<int64_t>(0), static_cast<int64_t>(7), false, true, ""},
    {"ASR-PAY-001", "", "lane", "lane", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "POOL"},
    {"ASR-PAY-001", "", "z", "y", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BYTES"},
    {"ASR-PAY-001", "", "new", "diff", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "REPLAY"},
    {"ASR-PAY-002", "", "claim-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PAY-002", "fail", "lost", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PAY-002", "fail", "lost", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PAY-002", "again", "claim-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PAY-003", "", "", "inv", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PAY-003", "", "", "inv", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PAY-003", "", "", "mutated", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "TERMS"},
    {"ASR-PAY-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "TERMS"},
    {"ASR-PAY-004", "payout", "mode", "routed", static_cast<int64_t>(1), static_cast<int64_t>(2), true, false, "UNQUALIFIED"},
    {"ASR-PAY-004", "refund", "mode", "routed", static_cast<int64_t>(1), static_cast<int64_t>(2), true, false, "UNQUALIFIED"},
    {"ASR-PLN-001", "replace", "session", "m9", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PLAN"},
    {"ASR-PLN-001", "", "", "m1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PLAN"},
    {"ASR-PLN-001", "", "frontier", "m1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PLN-001", "replace", "", "m2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PLAN"},
    {"ASR-PLN-001", "replace", "session", "m2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PLN-001", "replace", "other-model", "m3", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PLN-001", "", "other", "m4", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PLN-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CURSOR"},
    {"ASR-PLN-002", "", "wake-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PLN-002", "", "wake-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PLN-002", "", "wake-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PLN-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CURSOR"},
    {"ASR-PLN-002", "", "wake-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PLN-003", "", "z", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GEN"},
    {"ASR-PLN-003", "", "z", "", static_cast<int64_t>(0), static_cast<int64_t>(-5), false, false, "GEN"},
    {"ASR-PLN-003", "", "g4", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"ASR-PLN-003", "", "old", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "STALE"},
    {"ASR-PLN-003", "", "g4b", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"ASR-PLN-003", "", "no", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "STALE"},
    {"ASR-PLN-003", "", "g7", "", static_cast<int64_t>(0), static_cast<int64_t>(7), false, true, ""},
    {"ASR-PLN-003", "", "g6", "", static_cast<int64_t>(0), static_cast<int64_t>(6), false, false, "STALE"},
    {"ASR-PLN-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "COST"},
    {"ASR-PLN-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "COST"},
    {"ASR-PLN-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "COST"},
    {"ASR-PLN-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, true, ""},
    {"ASR-PLN-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "REPLAY"},
    {"ASR-PLN-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "COST"},
};

} // namespace

bool Liv14::Pass(std::string& err)
{
    Grp14 group;
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

bool Liv14::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv14::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv14::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv14::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv14::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
