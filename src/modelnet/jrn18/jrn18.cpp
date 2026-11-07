// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn18/jrn18.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/prof01/prof01.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct Call {
    const char* id;
    const char* text;
    int64_t aux;
    bool flag;
    const char* want;
};

const Call kCalls[] = {
    {"", "", static_cast<int64_t>(0), true, "ID"},
    {"no-such", "s1", static_cast<int64_t>(1), true, "ID"},
    {"no-such", "vllm", static_cast<int64_t>(1), true, "ID"},
    {"fresh-native-start", "", static_cast<int64_t>(-1), false, "FIELD"},
    {"fresh-native-start", "s1", static_cast<int64_t>(-1), false, "BOUND"},
    {"fresh-native-start", "s1", static_cast<int64_t>(101), false, "CAP"},
    {"fresh-native-start", "s1", static_cast<int64_t>(0), false, "ABSENT"},
    {"fresh-native-start", "s1", static_cast<int64_t>(0), true, "NOT_RUN"},
    {"fresh-native-start", "s1", static_cast<int64_t>(100), true, "NOT_RUN"},
    {"local-cpu-useful-model", "vllm", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"local-cpu-useful-model", "sglang", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"local-cpu-useful-model", "lmcache", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"local-cpu-useful-model", "nixl", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"local-cpu-useful-model", "mooncake", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"local-cpu-useful-model", "rdma", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"local-cpu-useful-model", "deepinfer", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"local-cpu-useful-model", "dualpipe", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"local-cpu-useful-model", "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"local-cpu-useful-model", "fp4", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"local-cpu-useful-model", "deepep", static_cast<int64_t>(1), true, "NOT_RUN"},
    {"local-cpu-useful-model", "vllm-extra", static_cast<int64_t>(1), true, "NOT_RUN"},
    {"fresh-native-start", "private trajectory", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA},
    {"private-case-revocation", "vllm", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"private-case-revocation", "private trajectory", static_cast<int64_t>(1), true, "NOT_RUN"},
};

const char* const kProfiles[] = {
    "fresh-native-start",
    "local-cpu-useful-model",
    "linux-sm100-deepinfer",
    "linux-ascend-deepinfer",
    "macos-portable",
    "windows-portable",
    "lan-two-physical-hosts",
    "wan-three-native-peers",
    "private-case-revocation",
    "deepinfer-exact-multirank-state",
    "whole-node-airgap",
    "offline-runtime-image",
    "economic-regtest",
    "failure-and-rollback",
};

static_assert(sizeof(kProfiles) / sizeof(kProfiles[0]) == 14, "fourteen profiles");

bool Refused(Prof01& prof, const char* id, const char* text, int64_t aux, bool flag, const char* want, std::string& err)
{
    const bool ok = prof.Apply(id, text, aux, flag, err);
    return !ok && err == want;
}

} // namespace

bool Jrn18::Pass(std::string& err)
{
    Prof01 prof;
    for (const Call& call : kCalls) {
        if (!Refused(prof, call.id, call.text, call.aux, call.flag, call.want, err)) return false;
    }
    for (const char* id : kProfiles) {
        if (!Refused(prof, id, "s1", static_cast<int64_t>(1), true, "NOT_RUN", err)) return false;
        if (!Refused(prof, id, "s1", static_cast<int64_t>(1), true, "NOT_RUN", err)) return false;
        if (prof.scenario_status() != "NOT_RUN") return false;
        if (prof.gpu_passed() || prof.windows_passed()) return false;
    }
    if (!Refused(prof, "windows-portable", "s1", static_cast<int64_t>(1), true, "NOT_RUN", err)) return false;
    if (!Refused(prof, "macos-portable", "s1", static_cast<int64_t>(1), true, "NOT_RUN", err)) return false;
    if (!Refused(prof, "linux-sm100-deepinfer", "s1", static_cast<int64_t>(1), true, "NOT_RUN", err)) return false;
    if (!Refused(prof, "linux-sm100-deepinfer", "deepinfer", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
    if (prof.gpu_passed() || prof.windows_passed()) return false;
    if (prof.scenario_status() != "NOT_RUN") return false;
    if (prof.qualified() || prof.release_qualified() || prof.hardware_qualified()) return false;
    err.clear();
    return true;
}

bool Jrn18::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn18::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn18::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn18::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn18::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
