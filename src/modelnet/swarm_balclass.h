// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_BALCLASS_H
#define BTX_MODELNET_SWARM_BALCLASS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of a requested move between balance classes.
 * Known classes are exactly escrow, collateral, channel, and earning.
 *
 * Atoms do not move between those classes. moved stays false on every
 * path. Nothing is broadcast. No hostnames or IPs are used.
 */
struct SwarmBalanceMove {
    std::string from_class;
    std::string to_class;
    int64_t atoms{0};
};

/**
 * Outcome of noting a balance-class move. moved stays false on every
 * path: atoms do not move between the four balance classes and nothing
 * is broadcast.
 */
struct SwarmBalanceMoveResult {
    bool moved{false};
    std::string code;
};

/**
 * Note a balance-class move without moving atoms.
 * Order, first match wins: empty from_class or to_class, atoms <= 0, or
 * either class outside escrow, collateral, channel, and earning is
 * BALANCE. Distinct known classes are SEPARATE. Otherwise the note is
 * NOTED and err is clear. moved stays false on every path. Atoms do not
 * move between the four balance classes and nothing is broadcast.
 */
SwarmBalanceMoveResult SwarmNoteBalanceClass(const SwarmBalanceMove& move, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_BALCLASS_H
