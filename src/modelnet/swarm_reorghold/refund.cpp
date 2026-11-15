// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/refund.h>

#include <modelnet/swarm_reorghold/codes.h>

namespace modelnet {

bool ReorgHoldRefund(ReorgHoldBook& book, const std::string& channel, std::string& err)
{
    if (!book.contains(channel)) {
        err = kReorgHoldChannel;
        return false;
    }
    const int64_t before = book.earned();
    const bool built_before = book.refund_built();
    if (book.reorged() || book.channel_frozen(channel)) {
        err = kReorgHoldFrozen;
    } else {
        err = kReorgHoldHeld;
    }
    if (book.refund_built() || built_before || book.earned() != before || book.paid(channel)) {
        err = kReorgHoldAtoms;
        return false;
    }
    return false;
}

} // namespace modelnet
