// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_refundheight.h>

#include <cstdint>

namespace modelnet {

SwarmRefundHeightResult SwarmNoteRefundHeight(const SwarmRefundHeightMove& move, std::string& err)
{
    SwarmRefundHeightResult result;
    result.changed = false;
    if (move.lot_id.empty() || move.height < 1) {
        result.changed = false;
        result.code = "HEIGHT";
        err = "HEIGHT";
        return result;
    }
    // An admin cannot move the sponsor refund height. Nothing is signed
    // and nothing is broadcast.
    if (move.want_change_height) {
        result.changed = false;
        result.code = "IMMUTABLE";
        err = "IMMUTABLE";
        return result;
    }
    result.changed = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
