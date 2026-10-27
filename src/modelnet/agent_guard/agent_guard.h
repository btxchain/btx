// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_AGENT_GUARD_AGENT_GUARD_H
#define BITCOIN_MODELNET_AGENT_GUARD_AGENT_GUARD_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * AgentGuard. One in-process permit record. No process is started.
 *
 * Permit, first match, stores nothing on failure. An empty id or an empty
 * text returns FIELD. Text exactly inprocess returns PROCESS.
 * process_present() stays false. Text that contains private returns
 * NIFDT_PRIVATE_DATA. Text exactly vllm, sglang, lmcache, nixl, mooncake,
 * rdma, deepinfer, dualpipe, fp8, or fp4 returns NIFDT_ENGINE_ABSENT.
 * The first id/text pair is stored. The same text again returns
 * NIFDT_REPLAY and keeps the first. A different text returns UNCHANGED.
 *
 * passed() stays false. launched(), gpu(), broadcast(), qualified(),
 * release_qualified(), and hardware_qualified() stay false.
 * hosts() and physical_hosts() stay 1. Hosts with n other than 1 returns
 * HOSTS. bytes_moved() stays 0. automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 */
class AgentGuard {
public:
    bool Permit(const std::string& id, const std::string& text, std::string& err);
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
    bool process_present() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_set{false};
    std::string m_id;
    std::string m_text;
};

} // namespace modelnet

#endif
