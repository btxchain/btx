// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/movekey.h>

#include <modelnet/swarm_adminhold/freeze.h>

namespace modelnet {

bool SwarmAdminHoldMoveKey::Apply(const SwarmAdminHoldBook& book,
                                   const std::string& channel,
                                   const std::vector<unsigned char>& next_key,
                                   std::string& err) const
{
    // The opened sponsor key stays. next_key is discarded.
    (void)next_key;
    return SwarmAdminHoldFreeze{}.refuse(book, channel, err);
}

} // namespace modelnet
