// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_spacingkeep.h>

namespace modelnet {

SwarmSpacingKeepResult SwarmKeepBlockSpacing(const SwarmSpacingKeep& chain, std::string& err)
{
    // Block spacing stays 90 seconds and is not a wall-clock guarantee.
    SwarmSpacingKeepResult result;
    result.guaranteed = false;
    result.seconds = 90;
    if (chain.chain_id.empty()) {
        result.code = "CHAIN";
        result.guaranteed = false;
        result.seconds = 90;
        err = "CHAIN";
        return result;
    }
    if (chain.want_guarantee) {
        result.code = "HELD";
        result.guaranteed = false;
        result.seconds = 90;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.guaranteed = false;
    result.seconds = 90;
    err.clear();
    return result;
}

} // namespace modelnet
