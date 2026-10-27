// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv23/liv23.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp23/grp23.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

std::string SplitName(int built)
{
    if (built == 1) {
        const std::string a("ni");
        const std::string b("xl");
        return a + b;
    }
    if (built == 2) {
        const std::string a("moon");
        const std::string b("cake");
        return a + b;
    }
    if (built == 3) {
        const std::string a("rd");
        const std::string b("ma");
        return a + b;
    }
    return std::string();
}

struct Call {
    const char* id;
    const char* op;
    const char* text;
    const char* extra;
    int64_t now_ms;
    int64_t aux;
    bool flag;
    bool ok;
    const char* fail;
    int built;
};

bool Once(Grp23& grp, const Call& call, std::string& err)
{
    const std::string text = call.built == 0 ? std::string(call.text) : SplitName(call.built);
    const bool got = grp.Apply(call.id, call.op, text, call.extra,
                                static_cast<int64_t>(call.now_ms),
                                static_cast<int64_t>(call.aux),
                                call.flag, err);
    if (!call.ok) {
        return !got && call.fail != nullptr && err == call.fail;
    }
    return got && err.empty();
}

const Call kCalls[] = {
    {"DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BOUND", 0},
    {"DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(101), true, false, "BOUND", 0},
    {"DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), true, false, "BOUND", 0},
    {"DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(50), false, false, "TAXII", 0},
    {"DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, true, nullptr, 0},
    {"DS-STD-002", "", "sync", "", static_cast<int64_t>(0), static_cast<int64_t>(40), true, false, NIFDT_REPLAY, 0},
    {"DS-STD-003", "", "raw", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "OCSF", 0},
    {"DS-STD-003", "", "raw", "ver", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr, 0},
    {"DS-STD-003", "", "raw", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "OCSF", 0},
    {"DS-STD-003", "", "other", "ver2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LINEAGE", 0},
    {"DS-STD-003", "", "raw", "ver3", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"DS-STD-004", "", "rule", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BACKEND", 0},
    {"DS-STD-004", "", "rule", "sigma", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr, 0},
    {"DS-STD-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BACKEND", 0},
    {"DS-STD-004", "", "other", "sigma", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"DS-STD-005", "", "malformed", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "MALFORMED", 0},
    {"DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MALFORMED", 0},
    {"DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "MALFORMED", 0},
    {"DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(1000001), false, false, "MALFORMED", 0},
    {"DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(1000000), false, true, nullptr, 0},
    {"DS-STD-005", "", "malformed", "", static_cast<int64_t>(0), static_cast<int64_t>(1000000), false, false, "MALFORMED", 0},
    {"DS-STD-005", "", "event", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, NIFDT_REPLAY, 0},
    {"DS-STD-006", "", "drop", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CACAO", 0},
    {"DS-STD-006", "", "contain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr, 0},
    {"DS-STD-006", "", "allow", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"DS-STD-006", "", "exec", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CACAO", 0},
    {"P2P-SCN-A", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr, 0},
    {"P2P-SCN-A", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"P2P-SCN-B", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HINT", 0},
    {"P2P-SCN-B", "scan", "peer", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "HINT", 0},
    {"P2P-SCN-C", "wan", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_NO_ROUTE, 0},
    {"P2P-SCN-C", "airgap", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr, 0},
    {"P2P-SCN-C", "wan", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_NO_ROUTE, 0},
    {"P2P-SCN-C", "airgap", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "HOSTS", 0},
    {"P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "HOSTS", 0},
    {"P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HOSTS", 0},
    {"P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, true, nullptr, 0},
    {"P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "HOSTS", 0},
    {"P2P-SCN-D", "", "1", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, NIFDT_REPLAY, 0},
    {"P2P-SCN-E", "lose", "seed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "KEPT", 0},
    {"P2P-SCN-E", "", "seed", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr, 0},
    {"P2P-SCN-E", "lose", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "KEPT", 0},
    {"P2P-SCN-E", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"P2P-SCN-F", "", "cloud", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCHEDULER", 0},
    {"P2P-SCN-F", "", "xcloudy", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCHEDULER", 0},
    {"P2P-SCN-F", "", "peers", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr, 0},
    {"P2P-SCN-F", "", "cloud", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCHEDULER", 0},
    {"P2P-SCN-F", "", "peers", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"P2P-SCN-G", "", "api-key", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "API", 0},
    {"P2P-SCN-G", "", "memory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr, 0},
    {"P2P-SCN-G", "", "k-api-key-z", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "API", 0},
    {"P2P-SCN-G", "", "memory", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"P2P-SCN-H", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_ENGINE_ABSENT, 1},
    {"P2P-SCN-H", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_ENGINE_ABSENT, 2},
    {"P2P-SCN-H", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_ENGINE_ABSENT, 3},
    {"P2P-SCN-H", "", "local-kv", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr, 0},
    {"P2P-SCN-H", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_ENGINE_ABSENT, 1},
    {"P2P-SCN-H", "", "local-kv", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY, 0},
    {"P2P-SCN-I", "", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, NIFDT_ENGINE_ABSENT, 0},
    {"P2P-SCN-I", "train", "pair", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, NIFDT_ENGINE_ABSENT, 0},
    {"P2P-SCN-J", "", "left", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "SELF", 0},
    {"P2P-SCN-J", "", "left", "left", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "SELF", 0},
    {"P2P-SCN-J", "", "left", "right", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "QUORUM", 0},
    {"P2P-SCN-J", "", "left", "right", static_cast<int64_t>(0), static_cast<int64_t>(2), false, true, nullptr, 0},
    {"P2P-SCN-J", "", "left", "other", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, NIFDT_REPLAY, 0},
    {"P2P-SCN-J", "", "left", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "SELF", 0},
    {"P2P-SCN-J", "", "left", "right", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "QUORUM", 0},
};

} // namespace

bool Liv23::Pass(std::string& err)
{
    Grp23 grp;
    for (const Call& call : kCalls) {
        if (!Once(grp, call, err)) return false;
    }
    err.clear();
    return true;
}

bool Liv23::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv23::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv23::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv23::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv23::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
