// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoleaf2.h>

#include <string>

namespace modelnet {

SwarmNotNoLeaf2Result SwarmNoteNotNoLeaf2(const SwarmNotNoLeaf2& note, std::string& err)
{
    SwarmNotNoLeaf2Result result;
    result.built = false;
    // A contributor HTLC note builds no third leaf.
    if (note.contract_id.empty()) {
        result.code = "CONTRACT";
        result.built = false;
        err = "CONTRACT";
        return result;
    }
    if (note.want_third) {
        result.code = "HELD";
        result.built = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.built = false;
    err.clear();
    return result;
}

} // namespace modelnet
