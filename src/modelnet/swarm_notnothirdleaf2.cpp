// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnothirdleaf2.h>

namespace modelnet {

// This note builds no third HTLC leaf and no refund leaf.
SwarmNotNoThirdLeaf2Result SwarmNoteNotNoThirdLeaf2(const SwarmNotNoThirdLeaf2& note, std::string& err)
{
    SwarmNotNoThirdLeaf2Result result;
    result.built = false;
    if (note.tx_id.empty()) {
        result.code = "TX";
        err = "TX";
        result.built = false;
        return result;
    }
    if (note.want_build) {
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
