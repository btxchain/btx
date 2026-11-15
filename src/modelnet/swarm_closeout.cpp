// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closeout.h>

namespace modelnet {

static constexpr int kCloseMarginBlocks = 160;

int SwarmCloseOut::margin() const
{
    return kCloseMarginBlocks;
}

bool SwarmCloseOut::Shrink(int requested, std::string& err)
{
    if (requested == kCloseMarginBlocks) {
        err.clear();
        return true;
    }
    // requested < 1 or requested != 160. margin() stays 160.
    err = "MARGIN";
    return false;
}

} // namespace modelnet
