// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP32_GRP32_H
#define BITCOIN_MODELNET_GRP32_GRP32_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Group 32. Closed gate for a second host, a second GPU, a vendor library,
 * NIXL, Mooncake, RDMA, FP8, DualPipe, an offline image execute, and a release.
 *
 * Note: an empty name returns NAME and stores nothing. A name for which
 * NifDtEngineLinked is false is stored absent and returns NIFDT_ENGINE_ABSENT.
 * memory and local are recorded and return true. A second note of a stored
 * name returns NIFDT_REPLAY. Any other nonempty name, including fp8, is stored
 * absent and returns NIFDT_ENGINE_ABSENT.
 *
 * Absent(name) is true after that stored refusal.
 * Hosts: n other than 1 returns HOSTS. hosts() and physical_hosts() stay 1.
 * Release returns NIFDT_UNQUALIFIED even after memory and local are recorded.
 * release_qualified(), hardware_qualified(), qualified(), advertised(),
 * launched(), gpu(), and broadcast() stay false.
 * Gpu and Vendor return NIFDT_ENGINE_ABSENT.
 * Spend returns NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 * automatic_spend() is "0".
 * This class opens no socket, starts no process, and runs no image execute.
 */
class Grp32 {
public:
    bool Note(const std::string& name, std::string& err);
    bool Absent(const std::string& name) const;
    bool linked(const std::string& name) const;
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
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::vector<std::string> m_absent;
    std::vector<std::string> m_noted;
};

} // namespace modelnet

#endif
