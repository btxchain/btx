// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prof02/prof02.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kKnown[] = {
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

const char* const kEngine[] = {
    "vllm",
    "sglang",
    "lmcache",
    "nixl",
    "mooncake",
    "rdma",
    "deepinfer",
    "dualpipe",
    "fp8",
    "fp4",
};

bool Known(const std::string& id)
{
    for (const char* row : kKnown) {
        if (id == row) return true;
    }
    return false;
}

bool EngineText(const std::string& text)
{
    for (const char* name : kEngine) {
        if (text == name) return true;
    }
    return false;
}

} // namespace

bool Prof02::stored(const std::string&) const
{
    return false;
}

std::string Prof02::text(const std::string&) const
{
    return std::string();
}

std::string Prof02::classification() const
{
    return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
}

bool Prof02::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    if (id.empty() || !Known(id)) {
        err = "ID";
        return false;
    }
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (aux < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    if (aux > static_cast<int64_t>(100)) {
        err = "CAP";
        return false;
    }
    if (!flag) {
        err = "ABSENT";
        return false;
    }
    if (EngineText(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    err = "NOT_RUN";
    return false;
}

bool Prof02::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Prof02::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prof02::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prof02::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prof02::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
