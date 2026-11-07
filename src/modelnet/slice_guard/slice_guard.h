// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SLICE_GUARD_SLICE_GUARD_H
#define BITCOIN_MODELNET_SLICE_GUARD_SLICE_GUARD_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Slice guard. Observe returns PROCESS and starts nothing.
 * process_present() and launched() stay false. passed(), gpu(),
 * broadcast(), qualified(), release_qualified(), and hardware_qualified()
 * stay false. hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 */
class SliceGuard {
public:
    bool Observe(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool process_present() const { return false; }
    bool launched() const { return false; }
    bool passed() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SLICE_GUARD_SLICE_GUARD_H
