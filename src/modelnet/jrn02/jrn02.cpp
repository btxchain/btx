// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn02/jrn02.h>

#include <modelnet/acc02/acc02.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct Step {
    const char* id;
    const char* text;
    int64_t aux;
    bool flag;
    const char* err;
};

// Arguments copied from acc02_tests. nullptr err is the accepted Apply.
// A named id is stored once; a later same text is REPLAY and a different
// text is UNCHANGED. Refusals run before that store, so one Acc02 can
// keep every expected refusal string.
const Step kSteps[] = {
    {"WIRE-004", "private?", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA},
    {"WIRE-004", "a?b", static_cast<int64_t>(1), true, "URI"},
    {"WIRE-004", "a#b", static_cast<int64_t>(1), true, "URI"},
    {"WIRE-004", "s1", static_cast<int64_t>(1), true, nullptr},
    {"WIRE-004", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"WIRE-004", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},
    {"WIRE-004", "s1?", static_cast<int64_t>(1), true, "URI"},

    {"ID-001", "private-note", static_cast<int64_t>(0), true, NIFDT_PRIVATE_DATA},
    {"ID-001", "s1", static_cast<int64_t>(0), false, "ABSENT"},
    {"ID-001", "s1", static_cast<int64_t>(0), true, "EXPIRED"},
    {"ID-001", "s1", static_cast<int64_t>(1), true, nullptr},
    {"ID-001", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"ID-001", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},
    {"ID-001", "s1", static_cast<int64_t>(0), true, "EXPIRED"},

    {"ID-002", "spend", static_cast<int64_t>(0), true, "ROLE"},
    {"ID-002", "spend", static_cast<int64_t>(1), true, "ROLE"},
    {"ID-002", "s1", static_cast<int64_t>(1), true, nullptr},
    {"ID-002", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"ID-002", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"ID-003", "widen", static_cast<int64_t>(1), true, "NARROW"},
    {"ID-003", "s1", static_cast<int64_t>(1), true, nullptr},
    {"ID-003", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"ID-003", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"ID-004", "shrink", static_cast<int64_t>(1), true, "THRESHOLD"},
    {"ID-004", "s1", static_cast<int64_t>(1), true, nullptr},
    {"ID-004", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"ID-004", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"NET-001", "tofu", static_cast<int64_t>(1), true, "TOFU"},
    {"NET-001", "s1", static_cast<int64_t>(1), true, nullptr},
    {"NET-001", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"NET-001", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"NET-002", "downgrade", static_cast<int64_t>(1), true, "DOWNGRADE"},
    {"NET-002", "s1", static_cast<int64_t>(1), true, nullptr},
    {"NET-002", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"NET-002", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"NET-003", "s1", static_cast<int64_t>(101), true, "CAP"},
    {"NET-003", "s1", static_cast<int64_t>(9), false, "ABSENT"},
    {"NET-003", "vllm", static_cast<int64_t>(9), true, NIFDT_ENGINE_ABSENT},
    {"NET-003", "s1", static_cast<int64_t>(9), true, "FANOUT"},
    {"NET-003", "s1", static_cast<int64_t>(100), true, "FANOUT"},
    {"NET-003", "s1", static_cast<int64_t>(8), true, nullptr},
    {"NET-003", "s1", static_cast<int64_t>(8), true, NIFDT_REPLAY},
    {"NET-003", "s2", static_cast<int64_t>(8), true, "UNCHANGED"},

    {"NET-004", "", static_cast<int64_t>(-1), false, "FIELD"},
    {"NET-004", "s1", static_cast<int64_t>(-1), true, "BOUND"},
    {"NET-004", "s1", static_cast<int64_t>(101), false, "CAP"},
    {"NET-004", "s1", static_cast<int64_t>(0), false, "ABSENT"},
    {"NET-004", "s1", static_cast<int64_t>(1), true, nullptr},
    {"NET-004", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"NET-004", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"GIT-001", "vllm", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"GIT-001", "sglang", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"GIT-001", "lmcache", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"GIT-001", "nixl", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"GIT-001", "mooncake", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"GIT-001", "rdma", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"GIT-001", "deepinfer", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"GIT-001", "dualpipe", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"GIT-001", "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"GIT-001", "fp4", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"GIT-001", "s1", static_cast<int64_t>(1), true, nullptr},
    {"GIT-001", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"GIT-001", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"GIT-002", "sha1", static_cast<int64_t>(1), true, "DIGEST"},
    {"GIT-002", "s1", static_cast<int64_t>(1), true, nullptr},
    {"GIT-002", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"GIT-002", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"GIT-003", "hook", static_cast<int64_t>(1), true, "HOOK"},
    {"GIT-003", "s1", static_cast<int64_t>(1), true, nullptr},
    {"GIT-003", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"GIT-003", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"GIT-004", "private note", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA},
    {"GIT-004", "s1", static_cast<int64_t>(1), true, nullptr},
    {"GIT-004", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"GIT-004", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"GIT-005", "s1", static_cast<int64_t>(1), true, "OID"},
    {"GIT-005", "sha1", static_cast<int64_t>(1), true, "OID"},
    {"GIT-005", "sha256-s1", static_cast<int64_t>(1), true, nullptr},
    {"GIT-005", "sha256-s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"GIT-005", "sha256-s2", static_cast<int64_t>(1), true, "UNCHANGED"},
    {"GIT-005", "s1", static_cast<int64_t>(1), true, "OID"},

    {"SCM-001", "s1", static_cast<int64_t>(1), true, nullptr},
    {"SCM-001", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"SCM-001", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},

    {"SCM-002", "conflict", static_cast<int64_t>(1), true, "CONFLICT"},
    {"SCM-002", "s1", static_cast<int64_t>(1), true, nullptr},
    {"SCM-002", "s1", static_cast<int64_t>(1), true, NIFDT_REPLAY},
    {"SCM-002", "s2", static_cast<int64_t>(1), true, "UNCHANGED"},
};

} // namespace

bool Jrn02::Pass(std::string& err)
{
    Acc02 eng;
    for (const Step& step : kSteps) {
        const bool accepted = eng.Apply(step.id, step.text, step.aux, step.flag, err);
        if (step.err != nullptr) {
            if (accepted || err != step.err) {
                return false;
            }
            continue;
        }
        if (!accepted || !err.empty()) {
            return false;
        }
    }
    err.clear();
    return true;
}

bool Jrn02::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn02::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn02::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn02::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn02::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
