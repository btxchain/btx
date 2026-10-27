// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/jrn19/jrn19.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/prof02/prof02.h>

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
    {"DT-NO-SUCH", "s1", static_cast<int64_t>(1), true, "ID"},
    {"DT-Q00", "s1", static_cast<int64_t>(1), true, "ID"},
    {"DT-Q19", "rdma", static_cast<int64_t>(1), true, "ID"},
    {"DT-Q01", "", static_cast<int64_t>(-1), false, "FIELD"},
    {"DT-Q01", "s1", static_cast<int64_t>(-1), true, "BOUND"},
    {"DT-Q01", "s1", static_cast<int64_t>(101), false, "CAP"},
    {"DT-Q01", "s1", static_cast<int64_t>(0), false, "ABSENT"},
    {"DT-Q04", "rdma", static_cast<int64_t>(1), false, "ABSENT"},
    {"DT-Q07", "fp8", static_cast<int64_t>(101), true, "CAP"},
    {"DT-Q01", "s1", static_cast<int64_t>(0), true, "NOT_RUN"},
    {"DT-Q01", "s1", static_cast<int64_t>(100), true, "NOT_RUN"},
    {"DT-Q02", "vllm", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q02", "sglang", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q02", "lmcache", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q02", "nixl", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q02", "mooncake", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q02", "rdma", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q02", "deepinfer", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q02", "dualpipe", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q02", "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q02", "fp4", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q04", "rdma", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q07", "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT},
    {"DT-Q02", "deepep", static_cast<int64_t>(1), true, "NOT_RUN"},
    {"DT-Q02", "vllm-extra", static_cast<int64_t>(1), true, "NOT_RUN"},
    {"DT-Q02", "private trajectory", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA},
    {"DT-Q03", "s1 private", static_cast<int64_t>(1), true, NIFDT_PRIVATE_DATA},
};

const char* const kIds[] = {
    "DT-Q01",
    "DT-Q02",
    "DT-Q03",
    "DT-Q04",
    "DT-Q05",
    "DT-Q06",
    "DT-Q07",
    "DT-Q08",
    "DT-Q09",
    "DT-Q10",
    "DT-Q11",
    "DT-Q12",
    "DT-Q13",
    "DT-Q14",
    "DT-Q15",
    "DT-Q16",
    "DT-Q17",
    "DT-Q18",
};

static_assert(sizeof(kIds) / sizeof(kIds[0]) == 18, "DT-Q01 through DT-Q18");

bool Refused(Prof02& prof, const char* id, const char* text, int64_t aux, bool flag, const char* want, std::string& err)
{
    const bool ok = prof.Apply(id, text, aux, flag, err);
    return !ok && err == want;
}

} // namespace

bool Jrn19::Pass(std::string& err)
{
    Prof02 prof;
    for (const Call& call : kCalls) {
        if (!Refused(prof, call.id, call.text, call.aux, call.flag, call.want, err)) return false;
    }
    if (prof.gpu() || prof.broadcast() || prof.bytes_moved() != static_cast<int64_t>(0)) return false;
    if (prof.scenario_status() != "NOT_RUN") return false;

    for (const char* id : kIds) {
        if (std::string(id) == "DT-Q04") {
            if (!Refused(prof, id, "rdma", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
            if (prof.stored(id)) return false;
        }
        if (std::string(id) == "DT-Q07") {
            if (!Refused(prof, id, "fp8", static_cast<int64_t>(1), true, NIFDT_ENGINE_ABSENT, err)) return false;
            if (prof.stored(id) || prof.gpu_passed()) return false;
        }
        if (!Refused(prof, id, "s1", static_cast<int64_t>(1), true, "NOT_RUN", err)) return false;
        if (prof.stored(id) || !prof.text(id).empty()) return false;
        if (prof.scenario_status() != "NOT_RUN") return false;
        if (prof.qualified() || prof.release_qualified()) return false;
        if (!Refused(prof, id, "s1", static_cast<int64_t>(1), true, "NOT_RUN", err)) return false;
        if (prof.stored(id)) return false;
        if (std::string(id) == "DT-Q12") {
            if (prof.Hosts(static_cast<int64_t>(2), err)) return false;
            if (err != "HOSTS") return false;
            if (prof.hosts() != static_cast<int64_t>(1)) return false;
            if (prof.physical_hosts() != static_cast<int64_t>(1)) return false;
            if (prof.bytes_moved() != static_cast<int64_t>(0)) return false;
            if (prof.stored("DT-Q12")) return false;
            if (prof.scenario_status() != "NOT_RUN") return false;
        }
    }

    if (prof.Release(err)) return false;
    if (err != NIFDT_UNQUALIFIED) return false;
    if (prof.release_qualified() || prof.qualified() || prof.hardware_qualified() || prof.advertised()) return false;
    if (prof.launched() || prof.gpu() || prof.gpu_passed() || prof.windows_passed() || prof.broadcast()) return false;
    if (prof.hosts() != static_cast<int64_t>(1)) return false;
    if (prof.physical_hosts() != static_cast<int64_t>(1)) return false;
    if (prof.bytes_moved() != static_cast<int64_t>(0)) return false;
    if (prof.scenario_status() != "NOT_RUN") return false;
    if (prof.Spend(err)) return false;
    if (err != NIFDT_AUTOMATIC_SPEND) return false;
    if (prof.automatic_spend() != NIFDT_AUTOMATIC_SPEND) return false;
    for (const char* id : kIds) {
        if (prof.stored(id)) return false;
    }
    if (prof.stored("DT-Q19")) return false;

    if (!Refused(prof, "DT-Q12", "s1", static_cast<int64_t>(1), true, "NOT_RUN", err)) return false;
    if (prof.stored("DT-Q12")) return false;
    if (prof.Hosts(static_cast<int64_t>(2), err)) return false;
    if (err != "HOSTS") return false;
    if (prof.hosts() != static_cast<int64_t>(1)) return false;
    if (prof.physical_hosts() != static_cast<int64_t>(1)) return false;
    if (prof.Hosts(static_cast<int64_t>(0), err)) return false;
    if (err != "HOSTS") return false;
    if (!prof.Hosts(static_cast<int64_t>(1), err) || !err.empty()) return false;
    if (prof.hosts() != static_cast<int64_t>(1)) return false;
    if (prof.bytes_moved() != static_cast<int64_t>(0)) return false;
    if (prof.broadcast() || prof.qualified() || prof.release_qualified()) return false;
    if (prof.scenario_status() != "NOT_RUN") return false;

    if (prof.Vendor(err)) return false;
    if (err != NIFDT_ENGINE_ABSENT) return false;
    if (prof.Gpu(err)) return false;
    if (err != NIFDT_ENGINE_ABSENT) return false;
    if (prof.classification() != "SIMULATION_NOT_HARDWARE_MEASUREMENT") return false;
    err.clear();
    return true;
}

bool Jrn19::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Jrn19::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Jrn19::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn19::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Jrn19::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
