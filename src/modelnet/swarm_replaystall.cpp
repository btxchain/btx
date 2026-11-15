// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_replaystall.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmReplayStallResult SwarmNoteReplayStall(const SwarmReplayStall& stall, std::string& err)
{
    SwarmReplayStallResult out;
    out.mined = false;

    if (stall.tip_height < 0 || stall.stall_height < 0) {
        out.code = "STALL";
        err = "STALL";
        return out;
    }
    if (stall.want_mine) {
        out.code = "MINE_REFUSED";
        err = "MINE_REFUSED";
        return out;
    }
    if (stall.tip_height >= stall.stall_height) {
        out.code = "HELD";
        err.clear();
        return out;
    }
    out.code = "BELOW";
    err.clear();
    return out;
}

} // namespace modelnet
