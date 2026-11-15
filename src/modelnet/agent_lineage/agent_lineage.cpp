// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/agent_lineage/agent_lineage.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool ExactEngine(const std::string& text)
{
    return text == "vllm" || text == "sglang" || text == "lmcache" ||
           text == "nixl" || text == "mooncake" || text == "rdma" ||
           text == "deepinfer" || text == "dualpipe" || text == "fp8" ||
           text == "fp4";
}

} // namespace

bool AgentLineage::stored(const std::string& parent) const
{
    for (const Row& row : m_rows) {
        if (row.parent == parent) return true;
    }
    return false;
}

std::string AgentLineage::child(const std::string& parent) const
{
    for (const Row& row : m_rows) {
        if (row.parent == parent) return row.child;
    }
    return std::string();
}

bool AgentLineage::Line(const std::string& parent, const std::string& child, std::string& err)
{
    if (parent.empty() || child.empty()) {
        err = "FIELD";
        return false;
    }
    if (child == "inherit") {
        err = "GRANT";
        return false;
    }
    if (parent.find("private") != std::string::npos || child.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (ExactEngine(parent) || ExactEngine(child)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    for (const Row& row : m_rows) {
        if (row.parent != parent) continue;
        if (row.child == child) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_rows.push_back(Row{parent, child});
    err.clear();
    return true;
}

bool AgentLineage::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool AgentLineage::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool AgentLineage::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool AgentLineage::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool AgentLineage::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
