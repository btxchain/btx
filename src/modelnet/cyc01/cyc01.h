// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_CYC01_CYC01_H
#define BITCOIN_MODELNET_CYC01_CYC01_H

#include <modelnet/node_cycle/node_cycle.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One call to the existing NodeCycle.
 * Pass default-constructs NodeCycle and calls Run once. It does not call
 * AcceptJournal. A later Pass returns the latched success and does not
 * call NodeCycle again.
 * steps() must be 12, generation() must be 0, and passed() must stay false.
 * Hosts accepts only 1. Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), gpu_passed(), windows_passed(), broadcast(),
 * qualified(), release_qualified(), hardware_qualified(), and passed()
 * stay false. hosts() and physical_hosts() are 1. bytes_moved() is 0.
 * generation() stays 0.
 * No file, socket, process, quarantine, GuardTable, or spend key.
 */
class Cyc01 {
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
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    int64_t generation() const { return static_cast<int64_t>(0); }

private:
    bool m_done{false};
};

} // namespace modelnet

#endif
