// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PRF01_PRF01_H
#define BITCOIN_MODELNET_PRF01_PRF01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Prf01 latches a local refusal. Pass calls the catalog reader on a missing
 * catalog and requires success with an empty result. It observes that model
 * DNS seeds are empty. A later Pass returns true without stepping again.
 * hosts() stays 1. automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), gpu_passed(), windows_passed(), passed(),
 * release_qualified(), and hardware_qualified() stay false.
 * Hosts with n other than 1 returns HOSTS.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * No socket, added seed, or process. A fresh start and a whole-node air gap
 * are a local refusal only. This is not a hardware qualification.
 */
class Prf01 {
public:
    bool Pass(std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_done{false};
};

} // namespace modelnet

#endif
