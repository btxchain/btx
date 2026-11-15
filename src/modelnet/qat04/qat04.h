// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_QAT04_QAT04_H
#define BITCOIN_MODELNET_QAT04_QAT04_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Qat04. Pass latches. A later Pass clears err and returns true.
 * Resume with a host count other than 1 returns HOSTS. physical_hosts()
 * stays 1. Serve returns NIFDT_ENGINE_ABSENT.
 * passed(), gpu_passed(), release_qualified(), and hardware_qualified()
 * stay false. Release returns NIFDT_UNQUALIFIED. Spend returns
 * NIFDT_AUTOMATIC_SPEND.
 * DT-Q10, DT-Q11, and DT-Q12 stay unqualified.
 * No file, socket, or process.
 */
class Qat04 {
public:
    bool Pass(std::string& err);
    bool Resume(int64_t n, std::string& err);
    bool Serve(std::string& err);
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
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_done{false};
};

} // namespace modelnet

#endif
