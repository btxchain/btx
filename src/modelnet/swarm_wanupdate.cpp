// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wanupdate.h>

namespace modelnet {

SwarmWanUpdateResult SwarmNoteWanUpdate(const SwarmWanUpdate& island, std::string& err)
{
    // A WAN weight exchange is held and moves no bytes.
    if (island.island_id.empty()) {
        err = "ISLAND";
        return SwarmWanUpdateResult{"ISLAND", false, 0};
    }
    if (island.want_exchange) {
        err = "HELD";
        return SwarmWanUpdateResult{"HELD", false, 0};
    }
    err.clear();
    return SwarmWanUpdateResult{"NOTED", false, 0};
}

} // namespace modelnet
