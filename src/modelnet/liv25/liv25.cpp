// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/liv25/liv25.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp30/grp30.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

struct Step {
    const char* id;
    const char* want;
};

// Same Apply calls grp30_tests makes for each requirement id, twice.
const Step kSteps[] = {
    {"NIF-KV-002", NIF_MANIFEST_INCOMPLETE},
    {"NIF-KV-002", NIF_MANIFEST_INCOMPLETE},
    {"NIF-KV-007", NIF_MANIFEST_CLAIM},
    {"NIF-KV-007", NIF_MANIFEST_CLAIM},
    {"NIF-QA-001", NIFDT_UNQUALIFIED},
    {"NIF-QA-001", NIFDT_UNQUALIFIED},
    {"DT-GRD-003", NIFDT_REPLAY},
    {"DT-GRD-003", NIFDT_REPLAY},
    {"DT-RLP-006", DT_ROLLOUT_ROUTE},
    {"DT-RLP-006", DT_ROLLOUT_ROUTE},
    {"DT-RLP-007", DT_ROLLOUT_SHORT},
    {"DT-RLP-007", DT_ROLLOUT_SHORT},
    {"DT-WAN-006", DT_DELAY_CHANGE},
    {"DT-WAN-006", DT_DELAY_CHANGE},
};

} // namespace

bool Liv25::Pass(std::string& err)
{
    Grp30 group;
    for (const Step& step : kSteps) {
        const bool ok = group.Apply(step.id, err);
        // The engine refusal is the accepted result. It does not qualify.
        if (ok || err != step.want) return false;
    }
    err.clear();
    return true;
}

bool Liv25::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv25::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Liv25::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Liv25::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
