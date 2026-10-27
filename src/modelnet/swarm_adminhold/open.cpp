// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/open.h>

#include <modelnet/swarm_adminhold/codes.h>
#include <modelnet/swarm_adminhold/gate.h>
#include <modelnet/swarm_adminhold/limits.h>

namespace modelnet {

bool SwarmAdminHoldOpen::Apply(SwarmAdminHoldBook& book,
                                const std::string& channel,
                                int64_t refund_height,
                                const std::vector<unsigned char>& sponsor_key,
                                std::string& err) const
{
    const std::string refusal = SwarmAdminHoldRefusal(book, channel, refund_height, sponsor_key);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!book.store(channel, refund_height, sponsor_key)) {
        if (book.contains(channel)) {
            err = kSwarmAdminHoldReplay;
        } else if (channel.empty()) {
            err = kSwarmAdminHoldChannel;
        } else if (refund_height < kSwarmAdminHoldMinHeight) {
            err = kSwarmAdminHoldHeight;
        } else {
            err = kSwarmAdminHoldKey;
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
