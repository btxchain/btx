// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/moveheight.h>

#include <modelnet/swarm_adminhold/freeze.h>

namespace modelnet {

bool SwarmAdminHoldMoveHeight::Apply(const SwarmAdminHoldBook& book,
                                      const std::string& channel,
                                      int64_t next_height,
                                      std::string& err) const
{
    // The opened refund height stays. next_height is discarded.
    (void)next_height;
    return SwarmAdminHoldFreeze{}.refuse(book, channel, err);
}

} // namespace modelnet
