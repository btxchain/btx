// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/gate.h>

#include <modelnet/swarm_adminhold/channel.h>
#include <modelnet/swarm_adminhold/codes.h>
#include <modelnet/swarm_adminhold/height.h>
#include <modelnet/swarm_adminhold/key.h>
#include <modelnet/swarm_adminhold/replay.h>

namespace modelnet {

std::string SwarmAdminHoldRefusal(const SwarmAdminHoldBook& book,
                                   const std::string& channel,
                                   int64_t refund_height,
                                   const std::vector<unsigned char>& sponsor_key)
{
    std::string err;
    if (!SwarmAdminHoldChannel{}.accept(channel, err)) return err;
    if (!SwarmAdminHoldHeight{}.accept(refund_height, err)) return err;
    if (!SwarmAdminHoldKey{}.accept(sponsor_key, err)) return err;
    if (SwarmAdminHoldIsReplay(book, channel)) return std::string{kSwarmAdminHoldReplay};
    return {};
}

} // namespace modelnet
