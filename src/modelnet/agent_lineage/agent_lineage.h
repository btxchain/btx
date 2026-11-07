// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_AGENT_LINEAGE_AGENT_LINEAGE_H
#define BITCOIN_MODELNET_AGENT_LINEAGE_AGENT_LINEAGE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Agent lineage. One child is stored for a parent.
 *
 * Line stores nothing on failure. An empty parent or child returns FIELD.
 * A child that is exactly inherit returns GRANT. A parent or child that
 * contains private returns NIFDT_PRIVATE_DATA. A parent or child that is
 * exactly vllm, sglang, lmcache, nixl, mooncake, rdma, deepinfer, dualpipe,
 * fp8, or fp4 returns NIFDT_ENGINE_ABSENT. The first parent/child pair is
 * stored. The same pair again returns NIFDT_REPLAY. A different child for
 * that parent returns UNCHANGED.
 *
 * Hosts with n other than 1 returns HOSTS. hosts() and physical_hosts()
 * stay 1. bytes_moved() stays 0. automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), broadcast(), qualified(), release_qualified(),
 * hardware_qualified(), and passed() stay false. Release returns
 * NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND. Vendor and Gpu
 * return NIFDT_ENGINE_ABSENT. This class opens no file, socket, or process
 * and grants no spend.
 */
class AgentLineage {
public:
    bool Line(const std::string& parent, const std::string& child, std::string& err);
    bool stored(const std::string& parent) const;
    std::string child(const std::string& parent) const;
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool passed() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string parent;
        std::string child;
    };
    std::vector<Row> m_rows;
};

} // namespace modelnet

#endif
