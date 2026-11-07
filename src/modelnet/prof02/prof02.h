// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROF02_PROF02_H
#define BITCOIN_MODELNET_PROF02_PROF02_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Profile 02. Closed records for DT-Q01 through DT-Q18.
 *
 * Apply, first match, stores nothing. An empty or unknown id returns ID.
 * Empty text returns FIELD. aux below 0 returns BOUND. aux above 100
 * returns CAP. flag false returns ABSENT. Exact text vllm, sglang,
 * lmcache, nixl, mooncake, rdma, deepinfer, dualpipe, fp8, or fp4 returns
 * NIFDT_ENGINE_ABSENT. Text that contains private returns
 * NIFDT_PRIVATE_DATA. Every known id then returns NOT_RUN and stores
 * nothing. DT-Q04 text rdma and DT-Q07 text fp8 hit the engine rule
 * before NOT_RUN.
 *
 * scenario_status() stays NOT_RUN. qualified() and release_qualified()
 * stay false. Release returns NIFDT_UNQUALIFIED. Spend returns
 * NIFDT_AUTOMATIC_SPEND. gpu_passed() and windows_passed() stay false.
 * launched(), gpu(), and broadcast() stay false. hosts() and
 * physical_hosts() stay 1. Hosts with n other than 1 returns HOSTS.
 * bytes_moved() stays 0. stored() stays false.
 * This class opens no file, socket, or process.
 */
class Prof02 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool stored(const std::string& id) const;
    std::string text(const std::string& id) const;
    std::string classification() const;
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
    bool advertised() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    std::string scenario_status() const { return "NOT_RUN"; }
};

} // namespace modelnet

#endif
