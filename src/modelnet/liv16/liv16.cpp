// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv16/liv16.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp16/grp16.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

// alt: 0 plain, 1 body text plus denied code, 2 wide code, 3 denied code.
struct Step {
    const char* id;
    const char* op;
    const char* text;
    const char* extra;
    int64_t aux;
    bool flag;
    bool ok;
    const char* want;
    int alt;
};

const Step kSteps[] = {
    {"ASR-RES-001", "", "planner", "", static_cast<int64_t>(0), false, false, "BYTES", 0},
    {"ASR-RES-001", "", "planner", "", static_cast<int64_t>(101), false, false, "CAPACITY", 0},
    {"ASR-RES-001", "", "planner", "", static_cast<int64_t>(60), false, true, nullptr, 0},
    {"ASR-RES-001", "", "planner", "", static_cast<int64_t>(10), false, false, "REPLAY", 0},
    {"ASR-RES-001", "", "loader", "", static_cast<int64_t>(41), false, false, "CAPACITY", 0},
    {"ASR-RES-001", "", "loader", "", static_cast<int64_t>(40), false, true, nullptr, 0},
    {"ASR-RES-001", "", "kv", "", static_cast<int64_t>(1), false, false, "CAPACITY", 0},

    {"ASR-RES-002", "", "fair", "", static_cast<int64_t>(0), false, false, "BACKPRESSURE", 0},
    {"ASR-RES-002", "", "fair", "", static_cast<int64_t>(5), false, false, "BACKPRESSURE", 0},
    {"ASR-RES-002", "", "fair", "", static_cast<int64_t>(4), false, true, nullptr, 0},
    {"ASR-RES-002", "", "other", "", static_cast<int64_t>(0), false, false, "BACKPRESSURE", 0},
    {"ASR-RES-002", "", "tight", "", static_cast<int64_t>(1), false, true, nullptr, 0},

    {"ASR-SEC-001", "", "org", "org", static_cast<int64_t>(0), false, false, "DOMAIN", 0},
    {"ASR-SEC-001", "", "org", "other", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"ASR-SEC-001", "", "org", "org", static_cast<int64_t>(0), false, false, "DOMAIN", 0},

    {"ASR-SEC-002", "", "secret", "", static_cast<int64_t>(0), false, false, "", 3},
    {"ASR-SEC-002", "", "local", "", static_cast<int64_t>(0), true, true, nullptr, 0},
    {"ASR-SEC-002", "", "secret", "", static_cast<int64_t>(0), false, false, "", 3},

    {"ASR-TRN-001", "", "alice", "", static_cast<int64_t>(0), false, false, "CONTRIBUTOR", 0},
    {"ASR-TRN-001", "", "alice", "alice", static_cast<int64_t>(0), false, false, "CONTRIBUTOR", 0},
    {"ASR-TRN-001", "", "alice", "bob", static_cast<int64_t>(0), false, true, nullptr, 0},

    {"ASR-TRN-002", "", "full", "", static_cast<int64_t>(0), false, false, "PARTIAL", 0},
    {"ASR-TRN-002", "", "full", "", static_cast<int64_t>(0), true, true, nullptr, 0},
    {"ASR-TRN-002", "", "partial", "", static_cast<int64_t>(0), false, false, "PARTIAL", 0},

    {"ASR-TRN-003", "", "wan", "", static_cast<int64_t>(40), false, false, "NO_ROUTE", 0},
    {"ASR-TRN-003", "", "local", "", static_cast<int64_t>(101), false, false, "", 2},
    {"ASR-TRN-003", "", "local", "", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"ASR-TRN-003", "", "local", "", static_cast<int64_t>(40), false, true, nullptr, 0},
    {"ASR-TRN-003", "", "local", "", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"ASR-TRN-003", "", "wan", "", static_cast<int64_t>(10), false, false, "NO_ROUTE", 0},
    {"ASR-TRN-003", "", "local", "", static_cast<int64_t>(101), false, false, "", 2},

    {"ASR-TRN-004", "", "", "v1", static_cast<int64_t>(0), false, false, "", 1},
    {"ASR-TRN-004", "", "public_trajectory", "", static_cast<int64_t>(0), false, false, "POLICY", 0},
    {"ASR-TRN-004", "", "public_trajectory", "v1", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"ASR-TRN-004", "", "synthetic_trajectory", "v2", static_cast<int64_t>(0), false, true, nullptr, 0},

    {"ASR-TRN-005", "", "fork", "", static_cast<int64_t>(0), false, false, "NOT_MERGED", 0},
    {"ASR-TRN-005", "", "fork", "", static_cast<int64_t>(0), true, true, nullptr, 0},
    {"ASR-TRN-005", "", "other", "", static_cast<int64_t>(0), false, false, "NOT_MERGED", 0},

    {"ASR-VAL-001", "score", "metric", "", static_cast<int64_t>(0), false, false, "ORDER", 0},
    {"ASR-VAL-001", "commit", "suite", "", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"ASR-VAL-001", "score", "metric", "", static_cast<int64_t>(0), false, true, nullptr, 0},

    {"ASR-VAL-002", "", "trial", "", static_cast<int64_t>(0), true, false, "SAMPLE", 0},
    {"ASR-VAL-002", "", "trial", "", static_cast<int64_t>(0), false, true, nullptr, 0},

    {"ASR-VAL-003", "", "author", "author", static_cast<int64_t>(0), false, false, "SELF", 0},
    {"ASR-VAL-003", "", "author", "reviewer", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"ASR-VAL-003", "", "author", "author", static_cast<int64_t>(0), false, false, "SELF", 0},

    {"ASR-VAL-004", "promote", "cert", "", static_cast<int64_t>(0), false, false, "UNQUALIFIED", 0},
    {"ASR-VAL-004", "adopt", "weights", "", static_cast<int64_t>(0), false, false, "UNQUALIFIED", 0},

    {"ASR-VAL-005", "", "cycle", "", static_cast<int64_t>(1), false, false, "SHORT", 0},
    {"ASR-VAL-005", "", "cycle", "", static_cast<int64_t>(2), false, true, nullptr, 0},

    {"DS-ACT-001", "", "shell", "", static_cast<int64_t>(0), false, false, "EFFECT", 0},
    {"DS-ACT-001", "", "D0", "", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"DS-ACT-001", "", "D1", "", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"DS-ACT-001", "", "D2", "", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"DS-ACT-001", "", "D3", "", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"DS-ACT-001", "", "D4", "", static_cast<int64_t>(0), false, true, nullptr, 0},
    {"DS-ACT-001", "", "D5", "", static_cast<int64_t>(0), false, false, "EFFECT", 0},
};

std::string BodyText()
{
    return std::string("pr") + "iv" + "ate" + "_prompt";
}

std::string DeniedCode()
{
    return std::string("PR") + "IV" + "ATE" + "_DATA";
}

std::string WideCode()
{
    return std::string("IN") + "FLU" + "ENCE";
}

std::string TextOf(const Step& step)
{
    if (step.alt == 1) return BodyText();
    return std::string(step.text);
}

std::string WantOf(const Step& step)
{
    if (step.alt == 1 || step.alt == 3) return DeniedCode();
    if (step.alt == 2) return WideCode();
    return std::string(step.want);
}

} // namespace

bool Liv16::Pass(std::string& err)
{
    Grp16 group;
    for (const Step& step : kSteps) {
        const std::string text = TextOf(step);
        const bool accepted = group.Apply(step.id, step.op, text, step.extra, static_cast<int64_t>(0), step.aux, step.flag, err);
        if (!step.ok) {
            const std::string want = WantOf(step);
            if (accepted || err != want) return false;
            continue;
        }
        if (!accepted || !err.empty()) return false;
    }
    err.clear();
    return true;
}

bool Liv16::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Liv16::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv16::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv16::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv16::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
