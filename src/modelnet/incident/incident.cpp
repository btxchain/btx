// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/incident/incident.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool EngineExact(const std::string& text)
{
    return text == "vllm" || text == "sglang" || text == "lmcache" ||
           text == "nixl" || text == "mooncake" || text == "rdma" ||
           text == "deepinfer" || text == "dualpipe" || text == "fp8" ||
           text == "fp4";
}

} // namespace

bool Incident::stored(const std::string& id) const
{
    return m_set && m_id == id;
}

std::string Incident::text(const std::string& id) const
{
    if (!m_set || m_id != id) return std::string();
    return m_text;
}

bool Incident::File(const std::string& id, const std::string& text, std::string& err)
{
    if (id.empty() || text.empty()) {
        err = INCIDENT_FIELD;
        return false;
    }
    if (text == "blocklist") {
        err = INCIDENT_SCOPE;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (EngineExact(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (m_set) {
        if (m_text == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = INCIDENT_UNCHANGED;
        return false;
    }
    m_id = id;
    m_text = text;
    m_set = true;
    err.clear();
    return true;
}

bool Incident::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = INCIDENT_HOSTS;
        return false;
    }
    err.clear();
    return true;
}

bool Incident::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Incident::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Incident::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Incident::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
