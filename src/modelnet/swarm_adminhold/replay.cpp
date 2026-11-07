// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/replay.h>

namespace modelnet {

bool SwarmAdminHoldIsReplay(const SwarmAdminHoldBook& book, const std::string& channel)
{
    if (channel.empty()) return false;
    return book.contains(channel);
}

} // namespace modelnet
