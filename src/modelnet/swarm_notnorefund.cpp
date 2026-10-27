// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorefund.h>

#include <string>

namespace modelnet {

SwarmNotNoRefundResult SwarmNoteNotNoRefund(const SwarmNotNoRefund& note, std::string& err)
{
    SwarmNotNoRefundResult result;
    result.counted = false;
    result.broadcast = false;
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.counted = false;
        result.broadcast = false;
        err = "CHANNEL";
        return result;
    }
    // Funding is not counted before the refund is signed.
    if (!note.refund_signed) {
        result.code = "UNSIGNED";
        result.counted = false;
        result.broadcast = false;
        err = "UNSIGNED";
        return result;
    }
    if (note.want_count_funding) {
        result.code = "UNSIGNED";
        result.counted = false;
        result.broadcast = false;
        err = "UNSIGNED";
        return result;
    }
    result.code = "NOTED";
    result.counted = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
