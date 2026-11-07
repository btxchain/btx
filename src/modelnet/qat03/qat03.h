// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_QAT03_QAT03_H
#define BITCOIN_MODELNET_QAT03_QAT03_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Qat03 covers DT-Q07, DT-Q08, and DT-Q09 without qualifying them.
 * Pass latches success. A later Pass returns that latch and does not
 * start work again. passed(), gpu_passed(), release_qualified(), and
 * hardware_qualified() stay false.
 * LowPrecision covers DT-Q07 and returns NIFDT_ENGINE_ABSENT.
 * ConditionalMemory covers DT-Q08 and returns NIFDT_UNQUALIFIED.
 * HeldOutTask covers DT-Q09 and returns NIFDT_UNQUALIFIED.
 * hosts() and physical_hosts() are 1. bytes_moved() is 0.
 * Spend returns NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), and broadcast() stay false.
 * No file, socket, or process.
 */
class Qat03 {
public:
    bool Pass(std::string& err);
    bool LowPrecision(std::string& err);
    bool ConditionalMemory(std::string& err);
    bool HeldOutTask(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool passed() const { return false; }
    bool gpu_passed() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_done{false};
};

} // namespace modelnet

#endif
