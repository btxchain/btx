// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/fleet_rollout/fleet_rollout.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool ExactAbsentEngine(const std::string& text)
{
    return text == "vllm" || text == "sglang" || text == "lmcache" ||
           text == "nixl" || text == "mooncake" || text == "rdma" ||
           text == "deepinfer" || text == "dualpipe" || text == "fp8" ||
           text == "fp4";
}

} // namespace

bool FleetRollout::stored(const std::string& id) const
{
    return m_on && m_id == id;
}

std::string FleetRollout::text(const std::string& id) const
{
    if (!m_on || m_id != id) return std::string();
    return m_text;
}

bool FleetRollout::Start(const std::string& id, const std::string& text, std::string& err)
{
    if (id.empty() || text.empty()) {
        err = "FIELD";
        return false;
    }
    if (text == "complete") {
        err = "STATE";
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (ExactAbsentEngine(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (m_on) {
        if (m_text == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_on = true;
    m_id = id;
    m_text = text;
    err.clear();
    return true;
}

bool FleetRollout::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool FleetRollout::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool FleetRollout::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool FleetRollout::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool FleetRollout::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
