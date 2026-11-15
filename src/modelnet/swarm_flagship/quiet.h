// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_QUIET_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * What this flagship plane is not allowed to do.
 * passed(), gpu_passed(), windows_passed(), and pay_passed() stay false.
 * launched(), gpu(), and broadcast() stay false.
 * bytes_moved() and atoms_moved() stay 0.
 * automatic_spend() stays "0".
 * There is no method that sets any of them. A flagship stage, a GPU run,
 * a Windows run, and a payment stay unpassed.
 */
class SwarmFlagshipQuiet {
public:
    bool passed() const;
    bool gpu_passed() const;
    bool windows_passed() const;
    bool pay_passed() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    std::uint64_t bytes_moved() const;
    std::uint64_t atoms_moved() const;
    std::string automatic_spend() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_QUIET_H
