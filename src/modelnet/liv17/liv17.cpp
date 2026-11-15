// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv17/liv17.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp17/grp17.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct Step {
    const char* id;
    const char* text;
    const char* extra;
    int64_t now_ms;
    int64_t aux;
    bool flag;
    bool accept;
    const char* deny;
};

constexpr char kRow004[] = {
    'P', 'R', 'I', 'V', 'A', 'T', 'E', '_', 'D', 'A', 'T', 'A', '\0',
};

const Step kSteps[] = {
    {"DS-ACT-002", "D3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "APPROVAL"},
    {"DS-ACT-002", "D3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, nullptr},
    {"DS-ACT-002", "D3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, NIFDT_REPLAY},
    {"DS-ACT-002", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-ACT-002", "D3", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "APPROVAL"},
    {"DS-ACT-002", "plain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, NIFDT_REPLAY},

    {"DS-ACT-003", "", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, "ASSET"},
    {"DS-ACT-003", "", "", static_cast<int64_t>(0), static_cast<int64_t>(11), false, false, "ASSET"},
    {"DS-ACT-003", "asset", "", static_cast<int64_t>(0), static_cast<int64_t>(11), false, false, "RADIUS"},
    {"DS-ACT-003", "asset", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BYTES"},
    {"DS-ACT-003", "asset", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "BYTES"},
    {"DS-ACT-003", "asset", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, true, nullptr},
    {"DS-ACT-003", "asset", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, NIFDT_REPLAY},
    {"DS-ACT-003", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(9), false, false, NIFDT_REPLAY},

    {"DS-ACT-004", "effect-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNKNOWN"},
    {"DS-ACT-004", "effect-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, true, nullptr},
    {"DS-ACT-004", "effect-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNKNOWN"},
    {"DS-ACT-004", "effect-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, "ALTERED"},
    {"DS-ACT-004", "effect-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, NIFDT_REPLAY},

    {"DS-ACT-005", "live", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CANARY"},
    {"DS-ACT-005", "live", "witness", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-ACT-005", "live", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "CANARY"},
    {"DS-ACT-005", "changed", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-ACT-005", "changed", "restore", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-ACT-005", "changed", "restore", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},

    {"DS-ACT-006", "retaliate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCOPE"},
    {"DS-ACT-006", "do-not-retaliate", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCOPE"},
    {"DS-ACT-006", "preserve", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-ACT-006", "retaliate-later", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SCOPE"},
    {"DS-ACT-006", "note", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},

    {"DS-AUTH-001", "", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ASSET"},
    {"DS-AUTH-001", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "ASSET"},
    {"DS-AUTH-001", "cust", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "MANDATE"},
    {"DS-AUTH-001", "cust", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-AUTH-001", "cust", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},

    {"DS-AUTH-002", "", "gen1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GENERATION"},
    {"DS-AUTH-002", "case", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GENERATION"},
    {"DS-AUTH-002", "", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "GENERATION"},
    {"DS-AUTH-002", "case", "gen1", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-AUTH-002", "other", "gen2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},

    {"DS-AUTH-003", "lease", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, false, "EXPIRED"},
    {"DS-AUTH-003", "lease", "", static_cast<int64_t>(6), static_cast<int64_t>(5), false, false, "EXPIRED"},
    {"DS-AUTH-003", "lease", "", static_cast<int64_t>(4), static_cast<int64_t>(5), false, true, nullptr},
    {"DS-AUTH-003", "lease", "", static_cast<int64_t>(5), static_cast<int64_t>(5), false, false, "EXPIRED"},
    {"DS-AUTH-003", "other", "", static_cast<int64_t>(1), static_cast<int64_t>(8), false, false, NIFDT_REPLAY},
    {"DS-AUTH-003", "later", "", static_cast<int64_t>(-2), static_cast<int64_t>(3), false, false, NIFDT_REPLAY},

    {"DS-AUTH-004", "scope-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-AUTH-004", "scope-b", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "UNCHANGED"},
    {"DS-AUTH-004", "scope-a", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},

    {"DS-AUTH-005", "contain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PURPOSE"},
    {"DS-AUTH-005", "read", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-AUTH-005", "effect", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-AUTH-005", "contain", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PURPOSE"},

    {"DS-AUTH-006", "prep", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, NIFDT_REVOKED},
    {"DS-AUTH-006", "prep", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-AUTH-006", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), true, false, NIFDT_REVOKED},
    {"DS-AUTH-006", "other", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},

    {"DS-DATA-001", "orig", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PROVENANCE"},
    {"DS-DATA-001", "orig", "prov", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-DATA-001", "altered", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "PROVENANCE"},
    {"DS-DATA-001", "altered", "prov2", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},

    {"DS-DATA-002", "sensor", "sensor", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SEPARATE"},
    {"DS-DATA-002", "sensor", "disputed", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-DATA-002", "sensor", "sensor", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "SEPARATE"},
    {"DS-DATA-002", "other", "fact", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
    {"DS-DATA-002", "sensor", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},

    {"DS-DATA-003", "", "", static_cast<int64_t>(0), static_cast<int64_t>(10), false, false, "BOUND"},
    {"DS-DATA-003", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(1001), false, false, "BOUND"},
    {"DS-DATA-003", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, "BOUND"},
    {"DS-DATA-003", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(-1), false, false, "BOUND"},
    {"DS-DATA-003", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(1000), false, true, nullptr},
    {"DS-DATA-003", "q", "", static_cast<int64_t>(0), static_cast<int64_t>(1), false, false, NIFDT_REPLAY},

    {"DS-DATA-004", "local-body", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, kRow004},
    {"DS-DATA-004", "local-body", "grant", static_cast<int64_t>(0), static_cast<int64_t>(0), false, true, nullptr},
    {"DS-DATA-004", "export", "", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, kRow004},
    {"DS-DATA-004", "export", "other", static_cast<int64_t>(0), static_cast<int64_t>(0), false, false, NIFDT_REPLAY},
};

} // namespace

bool Liv17::Pass(std::string& err)
{
    Grp17 eng;
    for (const Step& step : kSteps) {
        const bool got = eng.Apply(step.id, "", step.text, step.extra, step.now_ms, step.aux, step.flag, err);
        if (!step.accept) {
            if (step.deny == nullptr || got || err != step.deny) {
                return false;
            }
            continue;
        }
        if (!got || !err.empty()) {
            return false;
        }
    }
    return true;
}

bool Liv17::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv17::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv17::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv17::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv17::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
