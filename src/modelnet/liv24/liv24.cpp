// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv24/liv24.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp24/grp24.h>

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
    int q;
};

std::string Word()
{
    return std::string("in") + "ference";
}

std::string QText(int q)
{
    if (q == 1) return std::string("discovery coordination ") + Word();
    if (q == 2) return std::string("discovery coordination ") + Word() + " defense";
    if (q == 3) return std::string("defense ") + Word() + " coordination discovery";
    return std::string();
}

const Call kCalls[] = {
    {"P2P-SCN-K", "promote", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ORDER", 0},
    {"P2P-SCN-K", "rollback", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ORDER", 0},
    {"P2P-SCN-K", "activate", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED", 0},
    {"P2P-SCN-K", "stage", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ORDER", 0},
    {"P2P-SCN-K", "stage", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"P2P-SCN-K", "stage", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 0},
    {"P2P-SCN-K", "rollback", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 0},
    {"P2P-SCN-K", "activate", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED", 0},
    {"P2P-SCN-K", "stage", "gen-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"P2P-SCN-K", "activate", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED", 0},
    {"P2P-SCN-K", "rollback", "gen-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ORDER", 0},
    {"P2P-SCN-K", "rollback", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"P2P-SCN-K", "rollback", "gen-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 0},
    {"P2P-SCN-L", "", "hosted-team", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SERVICE", 0},
    {"P2P-SCN-L", "", "native-team", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"P2P-SCN-L", "", "still-hosted", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SERVICE", 0},
    {"P2P-SCN-L", "", "other-team", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 0},
    {"P2P-SCN-M", "settle", "funded", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, false, "UNQUALIFIED", 0},
    {"P2P-SCN-M", "", "again", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED", 0},
    {"P2P-SCN-N", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ORDER", 0},
    {"P2P-SCN-N", "", "committed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"P2P-SCN-N", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 0},
    {"P2P-SCN-N", "exit", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "KEPT", 0},
    {"P2P-SCN-O", "", "default", "extra-flag", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FLAG", 0},
    {"P2P-SCN-O", "", "custom", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FLAG", 0},
    {"P2P-SCN-O", "", "default", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"P2P-SCN-O", "", "default", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 0},
    {"P2P-SCN-O", "", "default", "extra-flag", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FLAG", 0},
    {"P2P-SCN-P", "gpu", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ENGINE_ABSENT", 0},
    {"P2P-SCN-P", "observe", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"P2P-SCN-P", "observe", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 0},
    {"P2P-SCN-P", "gpu", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ENGINE_ABSENT", 0},
    {"P2P-SCN-Q", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CORE", 1},
    {"P2P-SCN-Q", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 2},
    {"P2P-SCN-Q", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 3},
    {"P2P-SCN-Q", "remove", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "KEPT", 0},
    {"P2P-SCN-R", "", "present", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ABSENT", 0},
    {"P2P-SCN-R", "", "present", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, "", 0},
    {"P2P-SCN-R", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY", 0},
    {"P2P-SCN-R", "", "present", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ABSENT", 0},
    {"NIF-ISL-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(-5), false, false, "BOUND", 0},
    {"NIF-ISL-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), true, false, "BOUND", 0},
    {"NIF-ISL-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "HARDWARE", 0},
    {"NIF-ISL-004", "", "cost", "", static_cast<int64_t>(0), static_cast<int64_t>(4), true, true, "", 0},
    {"NIF-ISL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), true, false, "BOUND", 0},
    {"NIF-ISL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, false, "HARDWARE", 0},
    {"NIF-ISL-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(8), true, false, "REPLAY", 0},
    {"NIF-LAN-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HINT", 0},
    {"NIF-LAN-001", "", "announce", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"NIF-LAN-001", "", "again", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 0},
    {"NIF-LAN-002", "", "multicast", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HINT", 0},
    {"NIF-LAN-002", "", "elsewhere", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HINT", 0},
    {"NIF-LAN-002", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"NIF-LAN-002", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 0},
    {"NIF-LAN-002", "", "multicast", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HINT", 0},
    {"NIF-QA-007", "", "native", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "UNQUALIFIED", 0},
    {"NIF-QA-007", "promote", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED", 0},
    {"DT-CKP-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PARAM", 0},
    {"DT-CKP-004", "", "", "shape", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PARAM", 0},
    {"DT-CKP-004", "", "shape", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MAP", 0},
    {"DT-CKP-004", "", "shape", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MAP", 0},
    {"DT-CKP-004", "", "shape", "shape", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, "", 0},
    {"DT-CKP-004", "", "shape", "shape", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY", 0},
    {"DT-CKP-004", "", "shape", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MAP", 0},
    {"DT-REL-003", "", "image", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED", 0},
    {"DT-REL-003", "ship", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED", 0},
    {"DT-REL-007", "", "gpu lan wan security payment", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "UNQUALIFIED", 0},
    {"DT-REL-007", "", "partial", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED", 0},
};

} // namespace

bool Liv24::Pass(std::string& err)
{
    Grp24 group;
    for (const Call& call : kCalls) {
        const std::string text = call.q == 0 ? std::string(call.text) : QText(call.q);
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

bool Liv24::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv24::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv24::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv24::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv24::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
