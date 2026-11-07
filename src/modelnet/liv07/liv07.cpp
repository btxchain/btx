// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv07/liv07.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp07/grp07.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

std::string AltText(int alt)
{
    if (alt == 1) {
        const std::string a("f");
        const std::string b("p8");
        return a + b;
    }
    if (alt == 2) {
        const std::string a("f");
        const std::string b("p4-weight");
        return a + b;
    }
    if (alt == 3) {
        const std::string a("f");
        const std::string b("p4-cache");
        return a + b;
    }
    const std::string a("pri");
    const std::string b("vate");
    return a + b;
}

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
    int alt;
};

const Call kCalls[] = {
    {"DT-OPT-001", "", "adam", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "RECIPE", 0},
    {"DT-OPT-001", "", "adamw", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"DT-OPT-001", "", "sgd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FROZEN", 0},
    {"DT-OPT-002", "adam", "draft", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ROLE", 0},
    {"DT-OPT-002", "", "matrix", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "RULE", 0},
    {"DT-OPT-002", "adam", "matrix", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"DT-OPT-002", "sgd", "matrix", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"DT-OPT-002", "sgd", "scalar", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"DT-OPT-003", "", "finite", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FINITE", 0},
    {"DT-OPT-003", "", "finite", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, "", 0},
    {"DT-OPT-003", "", "finite", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FINITE", 0},
    {"DT-OPT-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "STATE", 0},
    {"DT-OPT-004", "", "m|s|r|k", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "JOURNAL", 0},
    {"DT-OPT-004", "", "m|s|r|k", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, "", 0},
    {"DT-OPT-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_ENGINE_ABSENT, 1},
    {"DT-OPT-005", "", "fp32", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, true, "", 0},
    {"DT-OPT-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_ENGINE_ABSENT, 2},
    {"DT-OPT-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 3},
    {"DT-OPT-007", "", "adamw", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"DT-OPT-007", "", "sgd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FROZEN", 0},
    {"DT-OPT-008", "draft", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, true, "", 0},
    {"DT-OPT-008", "backbone", "no", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "RECIPE", 0},
    {"DT-OPT-008", "backbone", "authorized", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"DT-DAT-001", "training", "public_trajectory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LICENSE", 0},
    {"DT-DAT-001", "training", "", "mit", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_PRIVATE_DATA, 4},
    {"DT-DAT-001", "other", "public_trajectory", "mit", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PURPOSE", 0},
    {"DT-DAT-001", "training", "public_trajectory", "mit", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"DT-DAT-002", "other", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "PURPOSE", 0},
    {"DT-DAT-002", "training", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, "", 0},
    {"DT-DAT-002", "validation", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, true, "", 0},
    {"DT-DAT-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PACK", 0},
    {"DT-DAT-003", "", "b1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"DT-DAT-003", "", "b2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"DT-DAT-004", "", "c1", "", static_cast<int64_t>(0), static_cast<int64_t>(7), false, false, "JOURNAL", 0},
    {"DT-DAT-004", "", "c1", "", static_cast<int64_t>(0), static_cast<int64_t>(7), true, true, "", 0},
    {"DT-DAT-004", "", "c2", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, false, "JOURNAL", 0},
    {"DT-DAT-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SHARD", 0},
    {"DT-DAT-005", "", "shard-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"DT-DAT-005", "", "shard-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"DT-DAT-006", "", "learnable", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FREEZE", 0},
    {"DT-DAT-006", "", "static", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"DT-DAT-007", "", "solution-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LEAK", 0},
    {"DT-DAT-007", "", "task", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
};

} // namespace

bool Liv07::Pass(std::string& err)
{
    Grp07 group;
    for (const Call& call : kCalls) {
        const std::string text = call.alt == 0 ? std::string(call.text) : AltText(call.alt);
        const bool ok = group.Apply(call.id, call.op, text, call.extra, call.now_ms, call.aux, call.flag, err);
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

bool Liv07::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv07::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv07::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv07::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv07::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
