// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrefundfirst.h>

#include <string>

namespace modelnet {

SwarmNotRefundFirstResult SwarmNoteNotRefundFirst(const SwarmNotRefundFirst& note, std::string& err)
{
    SwarmNotRefundFirstResult result;
    result.counted = false;
    result.broadcast = false;
    // An unready refund wins over a funding count. This note broadcasts nothing.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.counted = false;
        result.broadcast = false;
        err = "CHANNEL";
        return result;
    }
    if (!note.refund_ready) {
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
