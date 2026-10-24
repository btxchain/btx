// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/replay.h>

namespace modelnet {

bool SwarmDisputeStayIsReplay(const SwarmDisputeStayBook& book, const std::string& dispute)
{
    if (dispute.empty()) return false;
    return book.contains(dispute);
}

} // namespace modelnet
