// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_thirdleaf.h>

namespace modelnet {

// This record builds no third HTLC leaf and no refund leaf.
SwarmThirdLeafResult SwarmNoteThirdLeaf(const SwarmThirdLeaf& tx, std::string& err)
{
    SwarmThirdLeafResult result;
    result.built = false;
    if (tx.tx_id.empty()) {
        result.code = "TX";
        err = "TX";
        result.built = false;
        return result;
    }
    if (tx.want_build) {
        result.code = "HELD";
        err = "HELD";
        result.built = false;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.built = false;
    return result;
}

} // namespace modelnet
