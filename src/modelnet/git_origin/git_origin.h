// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GIT_ORIGIN_GIT_ORIGIN_H
#define BITCOIN_MODELNET_GIT_ORIGIN_GIT_ORIGIN_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory git origin digest for a name.
 *
 * Record, first match, stores nothing on failure. An empty name or digest
 * returns FIELD. A name or digest that contains private returns
 * NIFDT_PRIVATE_DATA. A digest exactly vllm, sglang, lmcache, nixl,
 * mooncake, rdma, deepinfer, dualpipe, fp8, or fp4 returns
 * NIFDT_ENGINE_ABSENT. A digest exactly sha1, or any digest that is not
 * 64 lowercase hex characters, returns DIGEST. The first accepted digest
 * for a name is stored. The same pair again returns NIFDT_REPLAY and keeps
 * the first. A different digest for that name returns UNCHANGED and keeps
 * the first.
 *
 * hosts() and physical_hosts() stay 1. Hosts with n other than 1 returns
 * HOSTS. bytes_moved() stays 0. automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), broadcast(), qualified(), release_qualified(),
 * hardware_qualified(), passed(), and process_present() stay false.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * This class opens no file, socket, or process.
 */
class GitOrigin {
public:
    bool Record(const std::string& name, const std::string& digest, std::string& err);
    bool stored(const std::string& name) const;
    std::string digest(const std::string& name) const;

    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

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
    std::map<std::string, std::string> m_rows;
};

} // namespace modelnet

#endif
