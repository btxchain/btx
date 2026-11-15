// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_QUIET_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Gauges this plane is not allowed to raise.
 * There is no setter. connected() and socket_opened() stay false.
 * launched(), gpu(), and broadcast() stay false.
 * bytes_moved() and atoms_moved() stay 0.
 * automatic_spend() stays "0".
 * This is not a connection, a transfer, or a payment.
 */
class SwarmExecNbhdQuiet {
public:
    bool connected() const;
    bool socket_opened() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    int64_t bytes_moved() const;
    std::string automatic_spend() const;
    int64_t atoms_moved() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_QUIET_H
