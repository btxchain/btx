// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv05/liv05.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp05/grp05.h>

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
    {"DT-EVD-001", "", "hardware", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CLASS"},
    {"DT-EVD-001", "", "documented", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-EVD-001", "", "hypothesis", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-EVD-002", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BASELINE"},
    {"DT-EVD-002", "", "b1", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-EVD-002", "", "b2", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ALTERED"},
    {"DT-EVD-003", "", "abc", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PIN"},
    {"DT-EVD-003", "", "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-EVD-003", "replace", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLACE"},
    {"DT-EVD-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MODEL"},
    {"DT-EVD-004", "", "grok-4.7-high", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-EVD-005", "git", "spec", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PRI" "VATE"},
    {"DT-EVD-005", "", "outside", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-EVD-006", "", "pass", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CLASS"},
    {"DT-EVD-006", "", "hardware", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-EVD-006", "", "release", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-EVD-007", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ATTRIBUTION"},
    {"DT-EVD-007", "", "DeepSeek", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-EVD-008", "", "complete", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNINSPECTED"},
    {"DT-EVD-008", "", "uninspected", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-NAT-001", "sidecar", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "OWNER"},
    {"DT-NAT-001", "btxd", "extra", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FLAG"},
    {"DT-NAT-001", "btxd", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-NAT-002", "", "c1", "", static_cast<int64_t>(10), static_cast<int64_t>(10), false, false, "EXPIRED"},
    {"DT-NAT-002", "", "c1", "", static_cast<int64_t>(9), static_cast<int64_t>(10), false, true, ""},
    {"DT-NAT-002", "commit", "c1", "", static_cast<int64_t>(9), static_cast<int64_t>(10), false, true, ""},
    {"DT-NAT-002", "commit", "c1", "", static_cast<int64_t>(9), static_cast<int64_t>(10), false, false, "REPLAY"},
    {"DT-NAT-003", "", "c1", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, false, "EXPIRED"},
    {"DT-NAT-003", "", "c1", "", static_cast<int64_t>(4), static_cast<int64_t>(5), false, true, ""},
    {"DT-NAT-004", "schedule", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ORDER"},
    {"DT-NAT-004", "reserve", "", "", static_cast<int64_t>(0), static_cast<int64_t>(101), false, false, "CAPACITY"},
    {"DT-NAT-004", "reserve", "", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, true, ""},
    {"DT-NAT-004", "schedule", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-NAT-005", "reserve", "", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, true, ""},
    {"DT-NAT-005", "cancel", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DT-NAT-005", "release", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PINNED"},
    {"DT-NAT-006", "publish", "ced", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED"},
    {"DT-NAT-006", "publish", "dense", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNQUALIFIED"},
    {"DT-NAT-007", "stage", "w", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, true, ""},
    {"DT-NAT-007", "commit", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "JOURNAL"},
    {"DT-NAT-007", "commit", "w", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DT-NAT-008", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "API"},
    {"DT-NAT-008", "wan", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "NO_ROUTE"},
    {"DT-NAT-008", "", "local", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
};

} // namespace

bool Liv05::Pass(std::string& err)
{
    Grp05 group;
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

bool Liv05::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv05::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv05::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv05::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv05::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
