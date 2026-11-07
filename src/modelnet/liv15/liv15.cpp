// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv15/liv15.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp15/grp15.h>

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
    {"ASR-PLN-005", "busy", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "QUIET"},
    {"ASR-PLN-005", "busy", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "QUIET"},
    {"ASR-PLN-005", "quiesce", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PLN-005", "quiesce", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PLN-005", "busy", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "QUIET"},
    {"ASR-PLN-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "QUORUM"},
    {"ASR-PLN-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, true, ""},
    {"ASR-PLN-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "REPLAY"},
    {"ASR-PLN-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "QUORUM"},
    {"ASR-PLN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "HISTORY"},
    {"ASR-PLN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), true, true, ""},
    {"ASR-PLN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "HISTORY"},
    {"ASR-PLN-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), true, false, "REPLAY"},
    {"ASR-PRG-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DELTA"},
    {"ASR-PRG-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(7), false, true, ""},
    {"ASR-PRG-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DELTA"},
    {"ASR-PRG-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "REPLAY"},
    {"ASR-PRG-002", "stall", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, true, ""},
    {"ASR-PRG-002", "stall", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PRG-002", "stall", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-4), true, true, ""},
    {"ASR-PRG-002", "stall", "", "", static_cast<int64_t>(0), static_cast<int64_t>(100), false, false, "UNCHANGED"},
    {"ASR-PRG-002", "stall", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "UNCHANGED"},
    {"ASR-PRG-003", "", "adam", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PRG-003", "", "adam", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PRG-003", "", "sgd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "RECIPE"},
    {"ASR-PRG-004", "kill", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "KEPT"},
    {"ASR-PRG-004", "kill", "", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, true, ""},
    {"ASR-PRG-004", "kill", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "KEPT"},
    {"ASR-PRG-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "REPLAY"},
    {"ASR-PRT-001", "", "json", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ENVELOPE"},
    {"ASR-PRT-001", "", "btx", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PRT-001", "", "btx", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PRT-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ENVELOPE"},
    {"ASR-PRT-002", "status", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "QUIET"},
    {"ASR-PRT-002", "status", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "QUIET"},
    {"ASR-PRT-002", "cancel", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PRT-002", "status", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PRT-002", "status", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PRT-002", "cancel", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PUB-001", "publish", "pack", "body", static_cast<int64_t>(0), static_cast<int64_t>(1), true, false, "OUTSIDE"},
    {"ASR-PUB-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "OUTSIDE"},
    {"ASR-PUB-002", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HISTORY"},
    {"ASR-PUB-002", "", "note", "hist", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PUB-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HISTORY"},
    {"ASR-PUB-002", "", "other", "hist", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-PUB-003", "", "readme", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DOC"},
    {"ASR-PUB-003", "", "readme", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"ASR-PUB-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DOC"},
    {"ASR-PUB-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"ASR-PUB-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LICENSE"},
    {"ASR-PUB-004", "", "mit", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"ASR-PUB-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LICENSE"},
    {"ASR-PUB-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"ASR-REC-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(11), false, true, ""},
    {"ASR-REC-001", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, true, ""},
    {"ASR-REC-001", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "REPLAY"},
    {"ASR-REC-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "REPLAY"},
    {"ASR-REC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, false, "PREFIX"},
    {"ASR-REC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "PREFIX"},
    {"ASR-REC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(5), true, true, ""},
    {"ASR-REC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, "PREFIX"},
    {"ASR-REC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), true, false, "REPLAY"},
};

} // namespace

bool Liv15::Pass(std::string& err)
{
    Grp15 group;
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

bool Liv15::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv15::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv15::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv15::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv15::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
