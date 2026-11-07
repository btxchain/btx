// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv01/liv01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp01/grp01.h>

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
    {"NIF-NAT-001", "sidecar", "", "", static_cast<int64_t>(0), false, false, "OWNER"},
    {"NIF-NAT-001", "btxd", "extra", "", static_cast<int64_t>(0), false, false, "FLAG"},
    {"NIF-NAT-001", "btxd", "", "", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-NAT-001", "btxd", "", "", static_cast<int64_t>(0), false, false, "REPLAY"},

    {"NIF-NAT-002", "grant", "id1", "", static_cast<int64_t>(0), false, false, "BIND"},
    {"NIF-NAT-002", "grant", "id1", "art|journal", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-NAT-002", "grant", "id1", "art|journal", static_cast<int64_t>(0), false, false, "REPLAY"},

    {"NIF-NAT-003", "", "", "", static_cast<int64_t>(0), false, false, "REQUEST"},
    {"NIF-NAT-003", "", "req1", "", static_cast<int64_t>(1), false, false, "JOURNAL"},
    {"NIF-NAT-003", "", "req1", "", static_cast<int64_t>(1), true, true, nullptr},
    {"NIF-NAT-003", "", "req2", "", static_cast<int64_t>(9), false, false, "JOURNAL"},

    {"NIF-NAT-004", "", "", "", static_cast<int64_t>(0), false, false, "BYTES"},
    {"NIF-NAT-004", "", "", "", static_cast<int64_t>(101), false, false, "CAPACITY"},
    {"NIF-NAT-004", "", "", "", static_cast<int64_t>(40), false, true, nullptr},
    {"NIF-NAT-004", "", "", "", static_cast<int64_t>(10), false, false, "REPLAY"},

    {"NIF-NAT-005", "other", "", "", static_cast<int64_t>(0), false, false, "WORKER"},
    {"NIF-NAT-005", "fail", "", "", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-NAT-005", "fail", "", "", static_cast<int64_t>(0), false, true, nullptr},

    {"NIF-NAT-006", "node", "release", "", static_cast<int64_t>(0), false, false, "CLASS"},
    {"NIF-NAT-006", "", "native", "", static_cast<int64_t>(0), false, false, "NAME"},
    {"NIF-NAT-006", "node", "native", "", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-NAT-006", "node", "component", "", static_cast<int64_t>(0), false, false, "REPLAY"},

    {"NIF-FORK-001", "", "abc", "", static_cast<int64_t>(0), false, false, "PIN"},
    {"NIF-FORK-001", "", "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01", "", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-FORK-001", "", "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01", "", static_cast<int64_t>(0), false, false, "REPLAY"},

    {"NIF-FORK-002", "", "", "", static_cast<int64_t>(0), false, false, "LICENSE"},
    {"NIF-FORK-002", "", "MIT", "", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-FORK-002", "", "Apache", "", static_cast<int64_t>(0), false, false, "REPLAY"},

    {"NIF-FORK-003", "", "", "", static_cast<int64_t>(0), false, false, "GENERATION"},
    {"NIF-FORK-003", "", "gen1", "", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-FORK-003", "", "gen2", "", static_cast<int64_t>(0), false, false, "GENERATION"},

    {"NIF-FORK-004", "", "step", "", static_cast<int64_t>(0), false, false, NIFDT_ENGINE_ABSENT},
    {"NIF-FORK-004", "", "step", "", static_cast<int64_t>(0), false, false, NIFDT_ENGINE_ABSENT},

    {"NIF-FORK-005", "", "wan", "", static_cast<int64_t>(2), false, false, "SCOPE"},
    {"NIF-FORK-005", "", "local", "", static_cast<int64_t>(0), false, false, "BATCH"},
    {"NIF-FORK-005", "", "local", "", static_cast<int64_t>(2), true, false, NIFDT_ENGINE_ABSENT},
    {"NIF-FORK-005", "", "local", "", static_cast<int64_t>(2), false, true, nullptr},

    {"NIF-FORK-006", "", "", "", static_cast<int64_t>(0), false, false, "DELTA"},
    {"NIF-FORK-006", "apply", "d1", "", static_cast<int64_t>(0), false, false, "UPGRADE"},
    {"NIF-FORK-006", "", "d1", "", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-FORK-006", "", "d2", "", static_cast<int64_t>(0), false, false, "REPLAY"},

    {"NIF-PROF-001", "", "", "", static_cast<int64_t>(0), false, false, "PLATFORM"},
    {"NIF-PROF-001", "", "linux", "", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-PROF-001", "", "windows", "", static_cast<int64_t>(0), false, false, "REPLAY"},

    {"NIF-PROF-002", "", "deepseek-v4.1", "", static_cast<int64_t>(0), false, false, "V41"},
    {"NIF-PROF-002", "", "", "", static_cast<int64_t>(0), false, false, "PROFILE"},
    {"NIF-PROF-002", "", "dense_gqa_v1", "", static_cast<int64_t>(0), false, true, nullptr},

    {"NIF-PROF-003", "", "", "", static_cast<int64_t>(0), false, false, "DOMAIN"},
    {"NIF-PROF-003", "", "cpu-fp32", "", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-PROF-003", "", "gpu", "", static_cast<int64_t>(0), false, false, "REPLAY"},

    {"NIF-PROF-004", "ab", "hardware", "", static_cast<int64_t>(0), false, false, "CLASS"},
    {"NIF-PROF-004", "abc", "throughput", "", static_cast<int64_t>(0), false, false, "DIGEST"},
    {"NIF-PROF-004", "aa", "throughput", "", static_cast<int64_t>(0), false, true, nullptr},
    {"NIF-PROF-004", "bb", "approximate", "", static_cast<int64_t>(0), false, true, nullptr},
};

} // namespace

bool Liv01::Pass(std::string& err)
{
    Grp01 g;
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

bool Liv01::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv01::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv01::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
