// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_QAT01_QAT01_H
#define BITCOIN_MODELNET_QAT01_QAT01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Qat01 is DT-Q01 through DT-Q03. It does not hardware-qualify them.
 *
 * Pass latches. The first Pass calls the existing public lifecycle once
 * and one dense CPU step once. A later Pass clears err and returns true
 * without calling either again.
 *
 * A GPU claim returns NIFDT_ENGINE_ABSENT. A multirank claim, Hosts with
 * n other than 1, returns HOSTS. hosts() and physical_hosts() stay 1.
 * passed(), gpu_passed(), release_qualified(), and hardware_qualified()
 * stay false. scenario_status() stays NOT_RUN.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * bytes_moved() stays 0. lifecycle_calls() and dense_steps() stay 1
 * after the latch.
 * No file, socket, or process.
 */
class Qat01 {
public:
    bool Pass(std::string& err);
    bool Gpu(std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    bool covered(const std::string& id) const;
    std::string scenario_status() const { return "NOT_RUN"; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool passed() const { return false; }
    bool process_present() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    int64_t lifecycle_calls() const { return m_lifecycle_calls; }
    int64_t dense_steps() const { return m_dense_steps; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_done{false};
    int64_t m_lifecycle_calls{0};
    int64_t m_dense_steps{0};
};

} // namespace modelnet

#endif
