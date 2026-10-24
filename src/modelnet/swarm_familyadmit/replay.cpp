// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/replay.h>

namespace modelnet {

bool SwarmFamilyAdmitIsReplay(const SwarmFamilyAdmitRoster& roster, const std::string& peer)
{
    if (peer.empty()) return false;
    return roster.contains(peer);
}

} // namespace modelnet
