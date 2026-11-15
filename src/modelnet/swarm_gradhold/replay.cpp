// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/replay.h>

namespace modelnet {

bool SwarmGradHoldIsReplay(const SwarmGradHoldBook& book, const std::string& update_id)
{
    if (update_id.empty()) return false;
    return book.contains(update_id);
}

} // namespace modelnet
