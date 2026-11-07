// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv09/liv09.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp09/grp09.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct Step {
    const char* id;
    const char* op;
    const char* text;
    const char* extra;
    int64_t aux;
    bool flag;
    bool ok;
    const char* want;
};

const Step kSteps[] = {
    {"DT-WAN-002", "", "diloco", "", static_cast<int64_t>(0), false, false, "NAME"},
    {"DT-WAN-002", "", "local-sgd", "", static_cast<int64_t>(0), false, true, nullptr},

    {"DT-WAN-003", "", "local-sgd", "", static_cast<int64_t>(0), false, false, "NAME"},
    {"DT-WAN-003", "", "diloco", "", static_cast<int64_t>(0), false, true, nullptr},
    {"DT-WAN-003", "qualify", "", "", static_cast<int64_t>(0), false, false, "UNQUALIFIED"},

    {"DT-WAN-004", "", "a", "", static_cast<int64_t>(0), false, true, nullptr},
    {"DT-WAN-004", "replace", "c", "b", static_cast<int64_t>(0), false, false, "SYNC"},
    {"DT-WAN-004", "replace", "c", "a", static_cast<int64_t>(0), false, true, nullptr},

    {"DT-WAN-005", "commit", "", "", static_cast<int64_t>(0), false, true, nullptr},
    {"DT-WAN-005", "partition", "", "", static_cast<int64_t>(0), false, true, nullptr},
    {"DT-WAN-005", "commit", "", "", static_cast<int64_t>(0), false, false, "PARTITION"},

    {"DT-WAN-007", "", "", "", static_cast<int64_t>(0), false, false, "EPOCH"},
    {"DT-WAN-007", "", "e1", "", static_cast<int64_t>(2), false, false, "JOURNAL"},
    {"DT-WAN-007", "", "e1", "", static_cast<int64_t>(2), true, true, nullptr},
    {"DT-WAN-007", "", "e2", "", static_cast<int64_t>(3), false, false, "JOURNAL"},

    {"DT-WAN-008", "m", "m", "", static_cast<int64_t>(0), false, false, "SELF"},
    {"DT-WAN-008", "fork", "child", "", static_cast<int64_t>(0), false, true, nullptr},
    {"DT-WAN-008", "distill", "teacher", "", static_cast<int64_t>(0), false, true, nullptr},

    {"DT-SEC-001", "", "", "", static_cast<int64_t>(0), false, false, "IDENTITY"},
    {"DT-SEC-001", "", "signed", "", static_cast<int64_t>(0), false, true, nullptr},

    {"DT-SEC-002", "norm", "", "", static_cast<int64_t>(0), false, false, "NORM"},
    {"DT-SEC-002", "sig", "", "", static_cast<int64_t>(0), false, false, "NORM"},

    {"DT-SEC-003", "", "private_trajectory", "", static_cast<int64_t>(0), false, false, "PRIVATE_DATA"},
    {"DT-SEC-003", "", "public_trajectory", "", static_cast<int64_t>(0), false, true, nullptr},

    {"DT-SEC-004", "", "", "", static_cast<int64_t>(0), false, false, "MANDATE"},
    {"DT-SEC-004", "", "m1", "", static_cast<int64_t>(0), false, true, nullptr},
    {"DT-SEC-004", "pay", "m1", "", static_cast<int64_t>(0), false, false, "HELD"},

    {"DT-SEC-005", "", "draft", "", static_cast<int64_t>(0), false, false, "CLASS"},
    {"DT-SEC-005", "", "synthetic", "", static_cast<int64_t>(0), false, true, nullptr},
    {"DT-SEC-005", "", "accepted", "", static_cast<int64_t>(0), false, true, nullptr},

    {"DT-SEC-006", "download", "", "", static_cast<int64_t>(0), false, false, "DOWNLOAD"},
    {"DT-SEC-006", "", "elf", "", static_cast<int64_t>(0), false, false, "CODE"},
    {"DT-SEC-006", "", "worker", "", static_cast<int64_t>(0), false, true, nullptr},

    {"DT-SEC-007", "release", "cand", "", static_cast<int64_t>(0), false, false, "UNQUALIFIED"},
    {"DT-SEC-007", "candidate", "cand", "", static_cast<int64_t>(0), false, true, nullptr},

    {"DT-SEC-008", "arm", "", "", static_cast<int64_t>(0), false, false, "DEADLINE"},
    {"DT-SEC-008", "arm", "", "", static_cast<int64_t>(20), false, true, nullptr},
    {"DT-SEC-008", "fail", "", "", static_cast<int64_t>(0), false, true, nullptr},

    {"DT-SIM-001", "", "", "", static_cast<int64_t>(0), false, false, "ASSUMPTION"},
    {"DT-SIM-001", "", "slots-not-time", "", static_cast<int64_t>(0), false, true, nullptr},
};

} // namespace

bool Liv09::Pass(std::string& err)
{
    Grp09 g;
    for (const Step& step : kSteps) {
        const bool accepted = g.Apply(step.id, step.op, step.text, step.extra, static_cast<int64_t>(0), step.aux, step.flag, err);
        if (!step.ok) {
            if (accepted || err != step.want) return false;
            continue;
        }
        if (!accepted || !err.empty()) return false;
    }
    err.clear();
    return true;
}

bool Liv09::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv09::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv09::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv09::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv09::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
