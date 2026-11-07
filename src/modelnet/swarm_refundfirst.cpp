// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_refundfirst.h>

namespace modelnet {

SwarmRefundFirstResult SwarmNoteRefundFirst(const SwarmRefundFirst& note, std::string& err)
{
    SwarmRefundFirstResult result;
    result.counted = false;
    result.broadcast = false;
    if (note.channel_id.empty()) {
        result.code = "FUND";
        err = "FUND";
        return result;
    }
    // UNSIGNED wins even when want_count_funding is true.
    // A refund must be signed before funding counts.
    if (!note.refund_signed) {
        result.code = "UNSIGNED";
        err = "UNSIGNED";
        return result;
    }
    // Asking to count funding does not count it.
    // A signed refund still does not make this note count funding.
    if (note.want_count_funding) {
        result.code = "HELD";
        result.counted = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.counted = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
