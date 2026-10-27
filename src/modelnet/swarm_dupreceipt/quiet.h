// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_QUIET_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Status this plane keeps fixed.
 * broadcast() stays false. mined() stays false.
 * bytes_moved() stays 0. automatic_spend() stays "0".
 * There is no setter for any of them.
 */
class SwarmDupQuiet {
public:
    bool broadcast() const;
    bool mined() const;
    int64_t bytes_moved() const;
    std::string automatic_spend() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_QUIET_H
