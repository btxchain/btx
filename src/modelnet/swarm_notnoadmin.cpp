// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoadmin.h>

#include <string>

namespace modelnet {

SwarmNotNoAdminResult SwarmNoteNotNoAdmin(const SwarmNotNoAdmin& note, std::string& err)
{
    SwarmNotNoAdminResult result;
    result.moved = false;
    result.height = 0;
    // An admin note does not move a sponsor refund key or height.
    if (note.admin_id.empty()) {
        result.code = "ADMIN";
        result.moved = false;
        result.height = 0;
        err = "ADMIN";
        return result;
    }
    if (note.want_move_refund) {
        result.code = "REFUSED";
        result.moved = false;
        result.height = 0;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.height = 0;
    err.clear();
    return result;
}

} // namespace modelnet
