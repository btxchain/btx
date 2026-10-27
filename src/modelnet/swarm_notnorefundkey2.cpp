// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorefundkey2.h>

#include <string>

namespace modelnet {

SwarmNotNoRefundKey2Result SwarmNoteNotNoRefundKey2(const SwarmNotNoRefundKey2& note, std::string& err)
{
    SwarmNotNoRefundKey2Result result;
    result.moved = false;
    // An admin note does not move the sponsor refund key.
    if (note.admin_id.empty()) {
        result.code = "ADMIN";
        result.moved = false;
        err = "ADMIN";
        return result;
    }
    if (note.want_move) {
        result.code = "HELD";
        result.moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
