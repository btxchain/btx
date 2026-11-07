// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv02/liv02.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp02/grp02.h>
#include <modelnet/identity.h>
#include <util/strencodings.h>

#include <cstdint>
#include <string>
#include <vector>

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
    {"NIF-PROF-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(7), false, false, "SEMANTIC"},
    {"NIF-PROF-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, true, ""},
    {"NIF-PROF-006", "", "", "", static_cast<int64_t>(10), static_cast<int64_t>(0), false, false, "BYTES"},
    {"NIF-PROF-006", "", "", "", static_cast<int64_t>(50), static_cast<int64_t>(60), false, false, "CAPACITY"},
    {"NIF-PROF-006", "", "", "", static_cast<int64_t>(10), static_cast<int64_t>(60), false, true, ""},
    {"NIF-PROF-006", "release", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PINNED"},
    {"NIF-EXEC-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "STATE"},
    {"NIF-EXEC-001", "s0", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "CHUNK"},
    {"NIF-EXEC-001", "s0", "c1", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, true, ""},
    {"NIF-EXEC-001", "s1", "c2", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "STALE"},
    {"NIF-EXEC-001", "s0", "c1", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "REPLAY"},
    {"NIF-EXEC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PIPE"},
    {"NIF-EXEC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(4097), false, false, "PIPE"},
    {"NIF-EXEC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(128), false, true, ""},
    {"NIF-EXEC-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(64), false, false, "REPLAY"},
    {"NIF-EXEC-003", "hold", "", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, true, ""},
    {"NIF-EXEC-003", "cancel", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"NIF-EXEC-003", "release", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PINNED"},
    {"NIF-EXEC-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REQUEST"},
    {"NIF-EXEC-004", "", "a,b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"NIF-EXEC-004", "", "a,c", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ALTERED"},
    {"NIF-EXEC-004", "", "a,b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"NIF-EXEC-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DEADLINE"},
    {"NIF-EXEC-005", "open", "", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, true, ""},
    {"NIF-EXEC-005", "cancel", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"NIF-EXEC-005", "drain", "", "", static_cast<int64_t>(10), static_cast<int64_t>(0), false, false, "EXPIRED"},
    {"NIF-EXEC-005", "drain", "", "", static_cast<int64_t>(9), static_cast<int64_t>(0), false, true, ""},
    {"NIF-EXEC-005", "drain", "", "", static_cast<int64_t>(9), static_cast<int64_t>(0), false, false, "UNCHANGED"},
    {"NIF-EXEC-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GRAMMAR"},
    {"NIF-EXEC-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1025), false, false, "GRAMMAR"},
    {"NIF-EXEC-006", "grammar", "", "", static_cast<int64_t>(0), static_cast<int64_t>(32), false, true, ""},
    {"NIF-EXEC-006", "tool", "search", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "DENIED"},
    {"NIF-EXEC-006", "tool", "search", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"NIF-KV-001", "rt", "model", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "COMPONENT"},
    {"NIF-KV-001", "rt", "model", "tenant|gen", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"NIF-KV-001", "rt", "model", "tenant|gen", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"NIF-KV-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "COMPONENT"},
    {"NIF-KV-003", "r1", "m1", "t1", static_cast<int64_t>(1), static_cast<int64_t>(0), false, true, ""},
    {"NIF-KV-003", "r1", "m1", "t1", static_cast<int64_t>(2), static_cast<int64_t>(0), false, false, "GENERATION"},
    {"NIF-KV-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), true, false, "ENGINE_ABSENT"},
    {"NIF-KV-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BYTES"},
    {"NIF-KV-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, true, ""},
    {"NIF-KV-005", "", "alloc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ENGINE_ABSENT"},
    {"NIF-KV-005", "", "bind", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ENGINE_ABSENT"},
    {"NIF-KV-006", "submit", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "RANK"},
    {"NIF-KV-006", "submit", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"NIF-KV-006", "restore", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MISSING"},
    {"NIF-KV-006", "submit", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, true, ""},
    {"NIF-KV-006", "restore", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"NIF-KV-008", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1025), false, false, "MEMORY"},
    {"NIF-KV-008", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(8), true, false, "ENGINE_ABSENT"},
    {"NIF-KV-008", "", "g1", "", static_cast<int64_t>(0), static_cast<int64_t>(8), false, true, ""},
    {"NIF-KV-008", "", "g2", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "GENERATION"},
    {"NIF-LAN-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PEER"},
    {"NIF-LAN-003", "", "peer-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "HINT"},
    {"NIF-LAN-003", "zz", "peer-a", "zz", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "KEY"},
    {"NIF-LAN-004", "", "wan", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCOPE"},
    {"NIF-LAN-004", "", "lan", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"NIF-LAN-004", "wan", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "NO_ROUTE"},
};

bool Run(Grp02& group, const Call& call, std::string& err)
{
    const bool ok = group.Apply(call.id, call.op, call.text, call.extra, call.now_ms, call.aux, call.flag, err);
    if (!call.accept) {
        if (ok) {
            err = "STEP";
            return false;
        }
        return err == call.want;
    }
    return ok && err.empty();
}

bool SignedPeer(Grp02& group, std::string& err)
{
    std::vector<unsigned char> pk;
    std::vector<unsigned char> sk;
    std::vector<unsigned char> sig;
    if (!GenerateMlDsa44(pk, sk, err)) return false;
    const std::string peer = "peer-a";
    const Span<const unsigned char> msg(reinterpret_cast<const unsigned char*>(peer.data()), peer.size());
    if (!SignMlDsa44(Span<const unsigned char>(sk.data(), sk.size()), msg, sig, err)) return false;
    const std::string op = HexStr(pk);
    const std::string extra = HexStr(sig);
    const Call accept{"NIF-LAN-003", op.c_str(), peer.c_str(), extra.c_str(), static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""};
    if (!Run(group, accept, err)) return false;
    const Call replay{"NIF-LAN-003", op.c_str(), peer.c_str(), extra.c_str(), static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"};
    return Run(group, replay, err);
}

} // namespace

bool Liv02::Pass(std::string& err)
{
    Grp02 group;
    for (const Call& call : kCalls) {
        if (std::string(call.id) == "NIF-LAN-004") {
            if (!SignedPeer(group, err)) return false;
            break;
        }
        if (!Run(group, call, err)) return false;
    }
    for (const Call& call : kCalls) {
        if (std::string(call.id) != "NIF-LAN-004") continue;
        if (!Run(group, call, err)) return false;
    }
    err.clear();
    return true;
}

bool Liv02::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv02::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv02::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv02::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv02::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
