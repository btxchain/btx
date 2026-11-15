// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/exit.h>

#include <modelnet/swarm_reorghold/codes.h>

namespace modelnet {

bool ReorgHoldExit(ReorgHoldBook& book, const std::string& channel, std::string& err)
{
    if (!book.contains(channel)) {
        err = kReorgHoldChannel;
        return false;
    }
    const int64_t before = book.earned();
    const int64_t channel_before = book.channel_earned(channel);
    const std::size_t channels_before = book.size();
    if (book.reorged() || book.channel_frozen(channel)) {
        err = kReorgHoldFrozen;
    } else {
        err = kReorgHoldOpen;
    }
    if (book.earned() != before || book.channel_earned(channel) != channel_before || book.size() != channels_before ||
        book.paid(channel) || book.exited(channel) || !book.contains(channel)) {
        err = kReorgHoldAtoms;
        return false;
    }
    return false;
}

} // namespace modelnet
