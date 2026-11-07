// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_QUIET_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Flags this plane is not allowed to raise.
 * There is no setter. launched(), gpu(), broadcast(), mined(), saved(),
 * qualified(), admitted(), and running() stay false. bytes_moved() and
 * atoms_moved() stay 0. automatic_spend() stays "0".
 * This is not a live fault, a GPU run, or a hardware injection.
 */
class SwarmFaultQuiet {
public:
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool broadcast() const;
    bool mined() const;
    bool saved() const;
    bool qualified() const;
    bool admitted() const;
    bool running() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_QUIET_H
