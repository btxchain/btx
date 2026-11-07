// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv18/liv18.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp18/grp18.h>

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
    {"DS-DATA-005", "", "do not ignore previous text", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "TAINT"},
    {"DS-DATA-005", "", "see the instruction", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "TAINT"},
    {"DS-DATA-005", "", "ordinary log", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-DATA-005", "", "ignore previous", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "TAINT"},
    {"DS-DATA-005", "", "later log", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-DATA-005", "", "instruction", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "TAINT"},

    {"DS-DATA-006", "", "gap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GAP"},
    {"DS-DATA-006", "", "clock", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-DATA-006", "", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GAP"},
    {"DS-DATA-006", "", "loss", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-DEL-001", "", "spec", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "OUTSIDE"},
    {"DS-DEL-001", "", "source", "extra", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "OUTSIDE"},

    {"DS-DEL-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LICENSE"},
    {"DS-DEL-002", "", "MIT", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-DEL-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LICENSE"},
    {"DS-DEL-002", "", "Apache", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-DEL-003", "", "readme", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DOC"},
    {"DS-DEL-003", "", "readme", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DS-DEL-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DOC"},
    {"DS-DEL-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},

    {"DS-DEL-004", "", "pool", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "ASSURANCE"},
    {"DS-DEL-004", "", "pool", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-DEL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "ASSURANCE"},
    {"DS-DEL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-DEL-005", "", "native", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FINGERPRINT"},
    {"DS-DEL-005", "", "native", "fp", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-DEL-005", "", "changed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FINGERPRINT"},
    {"DS-DEL-005", "", "changed", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-DEL-006", "", "push", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNAUTHORIZED"},
    {"DS-DEL-006", "", "publish", "extra", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "UNAUTHORIZED"},

    {"DS-EVAL-001", "", "ablation", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BASELINE"},
    {"DS-EVAL-001", "", "ablation", "central", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-EVAL-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BASELINE"},
    {"DS-EVAL-001", "", "other", "single", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-EVAL-002", "", "fast", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MEASURE"},
    {"DS-EVAL-002", "", "triage effect false", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MEASURE"},
    {"DS-EVAL-002", "", "triage effect false cost", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-EVAL-002", "", "no", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MEASURE"},
    {"DS-EVAL-002", "", "cost false effect triage", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-EVAL-003", "", "late", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DELAY"},
    {"DS-EVAL-003", "", "cold", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-EVAL-003", "", "warm", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-EVAL-003", "", "external", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-EVAL-003", "", "cold", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-EVAL-003", "", "warm", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-EVAL-003", "", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DELAY"},

    {"DS-EVAL-004", "", "scope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-EVAL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-EVAL-005", "", "same", "same", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SELF"},
    {"DS-EVAL-005", "", "review", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-EVAL-005", "", "same", "same", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SELF"},
    {"DS-EVAL-005", "", "next", "diff", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},

    {"DS-EVAL-006", "", "native", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED"},
    {"DS-EVAL-006", "", "production", "extra", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "UNQUALIFIED"},

    {"DS-HIRE-001", "", "model", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FINGERPRINT"},
    {"DS-HIRE-001", "", "model,runtime", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FINGERPRINT"},
    {"DS-HIRE-001", "", "model,runtime,tool", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-HIRE-001", "", "a,b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FINGERPRINT"},
    {"DS-HIRE-001", "", "x,y,z", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
};

} // namespace

bool Liv18::Pass(std::string& err)
{
    Grp18 group;
    for (const Call& call : kCalls) {
        const bool ok = group.Apply(call.id, call.op, call.text, call.extra, call.now_ms, call.aux, call.flag, err);
        if (!call.accept) {
            if (ok || err != call.want) return false;
            continue;
        }
        if (!ok || !err.empty()) return false;
    }
    err.clear();
    return true;
}

bool Liv18::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv18::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv18::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv18::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv18::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
