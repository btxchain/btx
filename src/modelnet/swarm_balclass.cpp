// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_balclass.h>

#include <cstdint>

namespace modelnet {
namespace {

bool KnownBalanceClass(const std::string& name)
{
    return name == "escrow" || name == "collateral" || name == "channel" || name == "earning";
}

} // namespace

SwarmBalanceMoveResult SwarmNoteBalanceClass(const SwarmBalanceMove& move, std::string& err)
{
    SwarmBalanceMoveResult result;
    result.moved = false;
    if (move.from_class.empty() || move.to_class.empty() || move.atoms <= 0 ||
        !KnownBalanceClass(move.from_class) || !KnownBalanceClass(move.to_class)) {
        result.code = "BALANCE";
        result.moved = false;
        err = "BALANCE";
        return result;
    }
    // Atoms do not move between the four balance classes and nothing
    // is broadcast.
    if (move.from_class != move.to_class) {
        result.code = "SEPARATE";
        result.moved = false;
        err = "SEPARATE";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
