// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_EXT01_EXT01_H
#define BITCOIN_MODELNET_EXT01_EXT01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Ext01 walks one in-memory origin, attestation, lineage, guard, incident,
 * promotion, rollout, and remote, then the slice passes and the qualify
 * observations. The first success latches. A later Pass clears err and
 * returns true. A step whose bool differs from the required result leaves
 * the latch clear and returns false with that err.
 *
 * hosts() and physical_hosts() stay 1. Hosts with n other than 1 returns
 * HOSTS. bytes_moved() stays 0. automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), gpu_passed(), windows_passed(), broadcast(),
 * qualified(), release_qualified(), hardware_qualified(), passed(), and
 * process_present() stay false. Release returns NIFDT_UNQUALIFIED. Spend
 * returns NIFDT_AUTOMATIC_SPEND. Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * This class opens no file, socket, or process.
 */
class Ext01 {
public:
    bool Pass(std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
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
    bool m_done{false};
};

} // namespace modelnet

#endif
