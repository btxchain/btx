// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PRF05_PRF05_H
#define BITCOIN_MODELNET_PRF05_PRF05_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Prf05 calls LoadLabDisk and latches that call.
 * The reader must return BTX035_RECOVERY_REQUIRED. A later Pass
 * returns the latched success and does not read again. This class
 * does not delete or replace lab.json. A missing directory or file
 * is left to LoadLabDisk, which does not create it and starts no
 * daemon.
 * Spend returns NIFDT_AUTOMATIC_SPEND. Release returns NIFDT_UNQUALIFIED.
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false. hosts() stays 1.
 */
class Prf05 {
public:
    bool Pass(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_done{false};
};

} // namespace modelnet

#endif
