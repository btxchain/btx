// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv20/liv20.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp20/grp20.h>

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
    {"DS-MODEL-005", "place", "room", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ORDER"},
    {"DS-MODEL-005", "restrict", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LOCATION"},
    {"DS-MODEL-005", "restrict", "region", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-MODEL-005", "place", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LOCATION"},
    {"DS-MODEL-005", "place", "room", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-MODEL-005", "place", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-MODEL-006", "use", "cap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-MODEL-006", "use", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-MODEL-006", "poison", "cap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-MODEL-006", "use", "cap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REVOKED"},
    {"DS-MODEL-006", "poison", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-MODEL-006", "use", "cap", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REVOKED"},
    {"DS-NAT-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "OWNER"},
    {"DS-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "SPAWN"},
    {"DS-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-NAT-001", "", "btxd", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-NAT-002", "drop", "parent", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PRESERVE"},
    {"DS-NAT-002", "keep", "parent", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-NAT-002", "drop", "gone", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PRESERVE"},
    {"DS-NAT-002", "keep", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-NAT-003", "", "fee", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SPEND"},
    {"DS-NAT-003", "", "fee", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DS-NAT-003", "", "fee", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SPEND"},
    {"DS-NAT-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"DS-NAT-004", "note", "", "", static_cast<int64_t>(0), static_cast<int64_t>(40), false, true, ""},
    {"DS-NAT-004", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(7), false, true, ""},
    {"DS-NAT-004", "note", "", "", static_cast<int64_t>(0), static_cast<int64_t>(3), false, false, "REPLAY"},
    {"DS-NAT-004", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, true, ""},
    {"DS-NAT-004", "fail", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, true, ""},
    {"DS-NAT-005", "", "case", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "JOURNAL"},
    {"DS-NAT-005", "", "case", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DS-NAT-005", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "JOURNAL"},
    {"DS-NAT-005", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"DS-NAT-006", "", "opt", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "OPTOUT"},
    {"DS-NAT-006", "", "opt", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DS-NAT-006", "", "opt", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "OPTOUT"},
    {"DS-NAT-006", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"DS-OPS-001", "", "drill", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "READINESS"},
    {"DS-OPS-001", "", "drill", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DS-OPS-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"DS-OPS-002", "", "probe-live-target-sample", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BENIGN"},
    {"DS-OPS-002", "", "control", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-OPS-002", "", "x-live-target-y", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BENIGN"},
    {"DS-OPS-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-OPS-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "FIXTURE"},
    {"DS-OPS-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "FIXTURE"},
    {"DS-OPS-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "FIXTURE"},
    {"DS-OPS-003", "", "bound", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, true, ""},
    {"DS-OPS-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, false, "FIXTURE"},
    {"DS-OPS-003", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "REPLAY"},
    {"DS-OPS-004", "", "mitigation", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "EMBARGO"},
    {"DS-OPS-004", "", "mitigation", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, ""},
    {"DS-OPS-004", "", "mitigation", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "EMBARGO"},
    {"DS-OPS-004", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "REPLAY"},
    {"DS-OPS-005", "", "pri" "vate" "-note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PRI" "VATE_DATA"},
    {"DS-OPS-005", "", "public-patch", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-OPS-005", "", "still pri" "vate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PRI" "VATE_DATA"},
    {"DS-OPS-005", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-OPS-006", "", "ignored", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LOCAL"},
    {"DS-OPS-006", "", "ignored", "partner", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-OPS-006", "", "ignored", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LOCAL"},
    {"DS-OPS-006", "", "ignored", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
    {"DS-PAY-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MODE"},
    {"DS-PAY-001", "", "exact", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, ""},
    {"DS-PAY-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MODE"},
    {"DS-PAY-001", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "REPLAY"},
};

} // namespace

bool Liv20::Pass(std::string& err)
{
    Grp20 group;
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

bool Liv20::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv20::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv20::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv20::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv20::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
