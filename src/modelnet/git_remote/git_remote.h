// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GIT_REMOTE_GIT_REMOTE_H
#define BITCOIN_MODELNET_GIT_REMOTE_GIT_REMOTE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One git remote name and url.
 * Empty name or url returns FIELD. A url exactly shell, or a url that does
 * not start with https://, returns HELPER and stores nothing. A name or url
 * containing private returns NIFDT_PRIVATE_DATA. Engine names vllm, sglang,
 * lmcache, nixl, mooncake, rdma, deepinfer, dualpipe, fp8, and fp4 return
 * NIFDT_ENGINE_ABSENT. The first name/url pair is stored. The same url again
 * returns NIFDT_REPLAY. A different url returns UNCHANGED.
 * hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), broadcast(), qualified(), release_qualified(),
 * hardware_qualified(), and passed() stay false.
 * Hosts with n other than 1 returns HOSTS.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * This class opens no socket and starts no process.
 */
class GitRemote {
public:
    bool Add(const std::string& name, const std::string& url, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool stored() const { return m_on; }
    std::string name() const { return m_name; }
    std::string url() const { return m_url; }

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
    std::string m_name;
    std::string m_url;
};

} // namespace modelnet

#endif
