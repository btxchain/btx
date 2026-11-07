// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv22/liv22.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp22/grp22.h>

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
    {"DS-POOL-005", "", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(101), false, false, "CAP"},
    {"DS-POOL-005", "", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "CAP"},
    {"DS-POOL-005", "", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-POOL-005", "", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-POOL-005", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-POOL-005", "", "m", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, false, "REPLAY"},
    {"DS-POOL-005", "", "wide", "", static_cast<int64_t>(0), static_cast<int64_t>(100), false, true, ""},
    {"DS-POOL-005", "", "wide", "", static_cast<int64_t>(0), static_cast<int64_t>(100), false, false, "REPLAY"},
    {"DS-POOL-005", "", "z", "", static_cast<int64_t>(0), static_cast<int64_t>(100), false, false, "REPLAY"},
    {"DS-POOL-005", "", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(101), false, false, "CAP"},
    {"DS-POOL-006", "", "self", "self", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SELF"},
    {"DS-POOL-006", "", "self", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-POOL-006", "", "self", "third", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-POOL-006", "", "self", "self", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SELF"},
    {"DS-POOL-006", "", "next", "z", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-REC-001", "", "origin-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SOURCE"},
    {"DS-REC-001", "", "origin-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DS-REC-001", "", "wipe", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SOURCE"},
    {"DS-REC-001", "", "origin-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"DS-REC-002", "", "leader-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-REC-002", "", "leader-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-REC-002", "other", "leader-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FENCE"},
    {"DS-REC-003", "", "kept", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REVOKED"},
    {"DS-REC-003", "", "kept", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-REC-003", "", "wipe", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REVOKED"},
    {"DS-REC-003", "", "kept", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-REC-004", "", "invoice", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-REC-004", "payrecover", "wipe", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "KEPT"},
    {"DS-REC-004", "", "invoice", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-REC-005", "", "hyp-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-REC-005", "correct", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-REC-005", "correct", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-REC-006", "", "partition clock response", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PARTIAL"},
    {"DS-REC-006", "", "partition clock response liquidity", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-REC-006", "", "partition clock response liquidity", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-REC-006", "", "partition clock response", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PARTIAL"},
    {"DS-SHARE-001", "", "no-mark", "alice", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "TLP"},
    {"DS-SHARE-001", "", "tlp-green", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "TLP"},
    {"DS-SHARE-001", "", "tlp-green", "alice", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-SHARE-001", "", "tlp-green", "bob", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-SHARE-002", "", "held", "", static_cast<int64_t>(10), static_cast<int64_t>(10), false, false, "EMBARGO"},
    {"DS-SHARE-002", "", "held", "", static_cast<int64_t>(10), static_cast<int64_t>(9), false, false, "EMBARGO"},
    {"DS-SHARE-002", "", "held", "", static_cast<int64_t>(10), static_cast<int64_t>(11), false, true, ""},
    {"DS-SHARE-002", "", "held", "", static_cast<int64_t>(12), static_cast<int64_t>(11), false, false, "EMBARGO"},
    {"DS-SHARE-002", "", "held", "", static_cast<int64_t>(10), static_cast<int64_t>(11), false, false, "REPLAY"},
    {"DS-SHARE-003", "", "public-note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SANITIZE"},
    {"DS-SHARE-003", "", "public-note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DS-SHARE-003", "", "wipe", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SANITIZE"},
    {"DS-SHARE-003", "", "public-note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"DS-SHARE-004", "", "aa", "bb", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LEAK"},
    {"DS-SHARE-004", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LEAK"},
    {"DS-SHARE-004", "", "aa", "aa", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-SHARE-004", "", "aa", "bb", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LEAK"},
    {"DS-SHARE-004", "", "aa", "aa", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-SHARE-005", "force", "boom", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LOCAL"},
    {"DS-SHARE-005", "retract", "note-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-SHARE-005", "force", "boom", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "LOCAL"},
    {"DS-SHARE-005", "retract", "note-1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-SHARE-006", "use", "row-1", "share", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CONSENT"},
    {"DS-SHARE-006", "use", "row-1", "share-only", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CONSENT"},
    {"DS-SHARE-006", "train", "row-1", "can-share-this", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CONSENT"},
    {"DS-SHARE-006", "train", "row-1", "train", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-SHARE-006", "train", "row-1", "share", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CONSENT"},
    {"DS-SHARE-006", "train", "row-1", "train", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-STD-001", "", "", "ext", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "STIX"},
    {"DS-STD-001", "", "indicator", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "STIX"},
    {"DS-STD-001", "", "indicator", "ext", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-STD-001", "", "indicator", "other-ext", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
};

} // namespace

bool Liv22::Pass(std::string& err)
{
    Grp22 group;
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

bool Liv22::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv22::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv22::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv22::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv22::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
