// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/open.h>

#include <modelnet/swarm_onechannel/codes.h>
#include <modelnet/swarm_onechannel/record.h>

#include <string>

namespace modelnet {

bool SwarmOneChannelClassifyOpen(const SwarmOneChannelSeat& seat, std::string& err)
{
    // A stored channel id is not a network open. The seat is only read so the
    // reservation cannot be mistaken for an open, and it is not written.
    static_cast<void>(seat);
    err = SWARM_ONECHANNEL_NOT_OPENED;
    return false;
}

} // namespace modelnet
