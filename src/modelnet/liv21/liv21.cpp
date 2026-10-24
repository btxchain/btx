// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv21/liv21.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp21/grp21.h>

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
    {"DS-PAY-002", "fund", "native", "own", static_cast<int64_t>(5), static_cast<int64_t>(9), true, false, "UNQUALIFIED"},
    {"DS-PAY-002", "refund", "payout", "", static_cast<int64_t>(6), static_cast<int64_t>(1), false, false, "UNQUALIFIED"},

    {"DS-PAY-003", "", "expiry fee stale", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PATH"},
    {"DS-PAY-003", "", "expiry fee stale watch", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-PAY-003", "", "watch stale fee expiry", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-PAY-004", "credit", "backing", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, false, "SEPARATE"},
    {"DS-PAY-004", "", "backing", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, true, ""},
    {"DS-PAY-004", "credit", "backing", "", static_cast<int64_t>(0), static_cast<int64_t>(99), false, false, "SEPARATE"},
    {"DS-PAY-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "REPLAY"},

    {"DS-PAY-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LIQUIDITY"},
    {"DS-PAY-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "LIQUIDITY"},
    {"DS-PAY-005", "", "prefund", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, true, ""},
    {"DS-PAY-005", "", "prefund", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "REPLAY"},
    {"DS-PAY-005", "", "prefund", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LIQUIDITY"},

    {"DS-PAY-006", "", "earned", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-PAY-006", "fail", "erased", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-PAY-006", "reorg", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-PAY-006", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-PLAN-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HYPOTHESIS"},
    {"DS-PLAN-001", "negative", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HYPOTHESIS"},
    {"DS-PLAN-001", "", "h1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-PLAN-001", "", "h2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-PLAN-001", "negative", "erase-me", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},

    {"DS-PLAN-002", "", "left", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SERIAL"},
    {"DS-PLAN-002", "", "left", "left", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SERIAL"},
    {"DS-PLAN-002", "", "left", "right", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-PLAN-002", "", "left", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-PLAN-002", "", "left", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SERIAL"},

    {"DS-PLAN-003", "", "signal", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PROGRESS"},
    {"DS-PLAN-003", "", "signal", "", static_cast<int64_t>(0), static_cast<int64_t>(-2), false, true, ""},
    {"DS-PLAN-003", "", "signal", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "REPLAY"},
    {"DS-PLAN-003", "", "signal", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PROGRESS"},

    {"DS-PLAN-004", "", "evidence", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"DS-PLAN-004", "", "replacement", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "REPLAY"},
    {"DS-PLAN-004", "retract", "wipe", "", static_cast<int64_t>(0), static_cast<int64_t>(99), false, true, ""},
    {"DS-PLAN-004", "", "replacement", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "REPLAY"},
    {"DS-PLAN-004", "retract", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},

    {"DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "COST"},
    {"DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "COST"},
    {"DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, true, ""},
    {"DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "REPLAY"},
    {"DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "COST"},
    {"DS-PLAN-005", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "COST"},

    {"DS-PLAN-006", "lost", "procedure", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "KEPT"},
    {"DS-PLAN-006", "", "procedure", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-PLAN-006", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-PLAN-006", "lost", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "KEPT"},

    {"DS-POOL-001", "", "budget", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "POOL"},
    {"DS-POOL-001", "", "readiness", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-POOL-001", "", "incident", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-POOL-001", "", "readiness", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-POOL-001", "", "family", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-POOL-001", "", "incident", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-POOL-001", "", "budget", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "POOL"},

    {"DS-POOL-002", "", "", "lot-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-POOL-002", "", "", "lot-a", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "COLLATERAL"},
    {"DS-POOL-002", "", "", "lot-b", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-POOL-003", "", "reconcile", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, false, "BALANCE"},
    {"DS-POOL-003", "", "reconcile", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "BALANCE"},
    {"DS-POOL-003", "", "reconcile", "", static_cast<int64_t>(0), static_cast<int64_t>(6), true, true, ""},
    {"DS-POOL-003", "", "reconcile", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "BALANCE"},
    {"DS-POOL-003", "", "reconcile", "", static_cast<int64_t>(0), static_cast<int64_t>(4), true, false, "REPLAY"},

    {"DS-POOL-004", "", "membership", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, false, "MEMBER"},
    {"DS-POOL-004", "", "dues", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "BYTES"},
    {"DS-POOL-004", "", "work", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BYTES"},
    {"DS-POOL-004", "", "readiness", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"DS-POOL-004", "", "work", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "REPLAY"},
    {"DS-POOL-004", "", "membership", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, false, "MEMBER"},
    {"DS-POOL-004", "", "work", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "BYTES"},
    {"DS-POOL-004", "", "readiness", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "REPLAY"},
};

} // namespace

bool Liv21::Pass(std::string& err)
{
    Grp21 group;
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

bool Liv21::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv21::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv21::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv21::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv21::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
