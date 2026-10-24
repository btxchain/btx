// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/open.h>

#include <modelnet/swarm_reorghold/codes.h>

namespace modelnet {

bool ReorgHoldOpen(ReorgHoldBook& book, const std::string& channel, int64_t earned, std::string& err)
{
    if (channel.empty()) {
        err = kReorgHoldChannel;
        return false;
    }
    if (earned < 0) {
        err = kReorgHoldAtoms;
        return false;
    }
    if (book.reorged()) {
        err = kReorgHoldFrozen;
        return false;
    }
    if (book.contains(channel)) {
        err = kReorgHoldReplay;
        return false;
    }
    if (!book.Insert(channel, earned)) {
        err = kReorgHoldAtoms;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
