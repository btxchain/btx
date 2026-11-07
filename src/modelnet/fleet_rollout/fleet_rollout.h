// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_FLEET_ROLLOUT_FLEET_ROLLOUT_H
#define BITCOIN_MODELNET_FLEET_ROLLOUT_FLEET_ROLLOUT_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * FleetRollout. One id/text pair.
 * Empty id or text returns FIELD. Text exactly complete returns STATE
 * and stores nothing. Text containing private returns NIFDT_PRIVATE_DATA.
 * Text exactly vllm, sglang, lmcache, nixl, mooncake, rdma, deepinfer,
 * dualpipe, fp8, or fp4 returns NIFDT_ENGINE_ABSENT. The first id/text
 * pair is stored. The same text again returns NIFDT_REPLAY. A different
 * text returns UNCHANGED.
 * hosts() and physical_hosts() stay 1. Hosts with n other than 1
 * returns HOSTS. bytes_moved() stays 0.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), broadcast(), qualified(), release_qualified(),
 * hardware_qualified(), and passed() stay false.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * No file, socket, process, or broadcast.
 */
class FleetRollout {
public:
    bool Start(const std::string& id, const std::string& text, std::string& err);
    bool stored(const std::string& id) const;
    std::string text(const std::string& id) const;
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
    bool m_on{false};
    std::string m_id;
    std::string m_text;
};

} // namespace modelnet

#endif
