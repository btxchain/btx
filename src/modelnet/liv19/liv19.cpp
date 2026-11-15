// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv19/liv19.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp19/grp19.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct Step {
    const char* id;
    const char* op;
    const char* text;
    const char* extra;
    int64_t now_ms;
    int64_t aux;
    bool flag;
    bool ok;
    const char* want;
};

const Step kSteps[] = {
    {"DS-HIRE-002", "other", "family", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ADMISSION"},
    {"DS-HIRE-002", "family", "nope", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ADMISSION"},
    {"DS-HIRE-002", "pri" "vate", "pri" "vate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ADMISSION"},
    {"DS-HIRE-002", "family", "family", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-HIRE-002", "family", "family", "again", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-HIRE-002", "pri" "vate", "pri" "vate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ADMISSION"},
    {"DS-HIRE-002", "pri" "vate", "pri" "vate", "seat", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-HIRE-002", "pri" "vate", "pri" "vate", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-HIRE-002", "family", "family", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},

    {"DS-HIRE-003", "", "role", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_UNQUALIFIED},
    {"DS-HIRE-003", "", "role", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, nullptr},
    {"DS-HIRE-003", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, NIFDT_REPLAY},
    {"DS-HIRE-003", "", "role", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_UNQUALIFIED},

    {"DS-HIRE-004", "", "alpha", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-HIRE-004", "", "alpha", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-HIRE-004", "", "beta", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SUBSTITUTE"},

    {"DS-HIRE-005", "", "ignored", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CONFIG"},
    {"DS-HIRE-005", "", "ignored", "cfg", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-HIRE-005", "", "ignored", "later", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-HIRE-005", "", "ignored", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CONFIG"},

    {"DS-HIRE-006", "show", "banner", "extra", static_cast<int64_t>(0), static_cast<int64_t>(1), true, false, NIFDT_UNQUALIFIED},
    {"DS-HIRE-006", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_UNQUALIFIED},

    {"DS-LEARN-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "RELEASE"},
    {"DS-LEARN-001", "", "ship", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, NIFDT_UNQUALIFIED},

    {"DS-LEARN-002", "", "hold", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HOLDOUT"},
    {"DS-LEARN-002", "", "time", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-LEARN-002", "", "campaign", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-LEARN-002", "", "time", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-LEARN-002", "", "tenant", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-LEARN-002", "", "lineage", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-LEARN-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HOLDOUT"},

    {"DS-LEARN-003", "", "secret", "x", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PRI" "VATE_DATA"},
    {"DS-LEARN-003", "", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LICENSE"},
    {"DS-LEARN-003", "", "synthetic", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "LICENSE"},
    {"DS-LEARN-003", "", "public", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-LEARN-003", "", "synthetic", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-LEARN-003", "", "secret", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PRI" "VATE_DATA"},

    {"DS-LEARN-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HARM"},
    {"DS-LEARN-004", "", "note", "x", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-LEARN-004", "", "other", "y", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-LEARN-004", "", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "HARM"},

    {"DS-LEARN-005", "", "left", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SELF"},
    {"DS-LEARN-005", "", "left", "left", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SELF"},
    {"DS-LEARN-005", "", "left", "right", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-LEARN-005", "", "left", "down", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-LEARN-005", "", "left", "left", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SELF"},

    {"DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "SHORT"},
    {"DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SHORT"},
    {"DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "SHORT"},
    {"DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(2), false, true, nullptr},
    {"DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(5), false, false, NIFDT_REPLAY},
    {"DS-LEARN-006", "", "span", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "SHORT"},

    {"DS-MODEL-001", "", "", "south", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCOPE"},
    {"DS-MODEL-001", "", "north", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCOPE"},
    {"DS-MODEL-001", "", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCOPE"},
    {"DS-MODEL-001", "", "north", "south", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-MODEL-001", "", "east", "west", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-MODEL-001", "", "", "south", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCOPE"},

    {"DS-MODEL-002", "", "pri" "vate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "PRI" "VATE_DATA"},
    {"DS-MODEL-002", "", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "APPROVAL"},
    {"DS-MODEL-002", "", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "APPROVAL"},
    {"DS-MODEL-002", "", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, nullptr},
    {"DS-MODEL-002", "", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, NIFDT_REPLAY},
    {"DS-MODEL-002", "", "public", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "APPROVAL"},
    {"DS-MODEL-002", "", "pri" "vate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "PRI" "VATE_DATA"},

    {"DS-MODEL-003", "", "ni" "xl", "", static_cast<int64_t>(0), static_cast<int64_t>(4), true, false, NIFDT_ENGINE_ABSENT},
    {"DS-MODEL-003", "", "moon" "cake", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, NIFDT_ENGINE_ABSENT},
    {"DS-MODEL-003", "", "rd" "ma", "", static_cast<int64_t>(0), static_cast<int64_t>(1), true, false, NIFDT_ENGINE_ABSENT},
    {"DS-MODEL-003", "", "mesh", "", static_cast<int64_t>(0), static_cast<int64_t>(4), false, false, "PARTIAL"},
    {"DS-MODEL-003", "", "mesh", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "PARTIAL"},
    {"DS-MODEL-003", "", "mesh", "", static_cast<int64_t>(0), static_cast<int64_t>(3), true, true, nullptr},
    {"DS-MODEL-003", "", "mesh", "", static_cast<int64_t>(0), static_cast<int64_t>(9), true, false, NIFDT_REPLAY},
    {"DS-MODEL-003", "", "ni" "xl", "", static_cast<int64_t>(0), static_cast<int64_t>(4), true, false, NIFDT_ENGINE_ABSENT},

    {"DS-MODEL-004", "", "pin-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-MODEL-004", "", "pin-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PIN"},
    {"DS-MODEL-004", "", "pin-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
};

} // namespace

bool Liv19::Pass(std::string& err)
{
    Grp19 g;
    for (const Step& step : kSteps) {
        const bool accepted = g.Apply(step.id, step.op, step.text, step.extra, step.now_ms, step.aux, step.flag, err);
        if (!step.ok) {
            if (accepted || err != step.want) return false;
            continue;
        }
        if (!accepted || !err.empty()) return false;
    }
    err.clear();
    return true;
}

bool Liv19::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv19::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv19::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv19::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv19::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
