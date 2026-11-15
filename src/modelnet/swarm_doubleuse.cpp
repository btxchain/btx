// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_doubleuse.h>

namespace modelnet {

SwarmDoubleUseResult SwarmNoteDoubleUse(const SwarmDoubleUse& use, std::string& err)
{
    SwarmDoubleUseResult result;
    result.accepted = false;
    if (use.outpoint.empty()) {
        result.code = "OUTPOINT";
        err = "OUTPOINT";
        return result;
    }
    if (use.escrow_lot && use.channel_collateral) {
        result.code = "DOUBLE_USE";
        err = "DOUBLE_USE";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
