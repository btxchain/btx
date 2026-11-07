// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_exactstall.h>

namespace modelnet {

SwarmExactStallResult SwarmHoldExactMine(const SwarmExactStall& chain, std::string& err)
{
    SwarmExactStallResult result;
    result.mined = false;
    result.blocks = 0;
    // A mine request past the ExactReplay stall is held and mines nothing.
    if (chain.chain_id.empty()) {
        result.code = "CHAIN";
        result.mined = false;
        result.blocks = 0;
        err = "CHAIN";
        return result;
    }
    if (chain.want_mine) {
        result.code = "HELD";
        result.mined = false;
        result.blocks = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.mined = false;
    result.blocks = 0;
    err.clear();
    return result;
}

} // namespace modelnet
