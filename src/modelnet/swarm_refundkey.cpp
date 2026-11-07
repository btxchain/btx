// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_refundkey.h>

namespace modelnet {

SwarmRefundKeyResult SwarmNoteRefundKey(const SwarmRefundKeyMove& move, std::string& err)
{
    SwarmRefundKeyResult result;
    result.moved = false;
    if (move.lot_id.empty()) {
        result.moved = false;
        result.code = "REFUND";
        err = "REFUND";
        return result;
    }
    // An admin cannot move the sponsor refund key. Nothing is signed
    // and nothing is broadcast.
    if (move.want_move_refund_key) {
        result.moved = false;
        result.code = "IMMUTABLE";
        err = "IMMUTABLE";
        return result;
    }
    result.moved = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
