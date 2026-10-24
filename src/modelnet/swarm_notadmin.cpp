// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notadmin.h>

#include <string>

namespace modelnet {

SwarmNotAdminResult SwarmNoteNotAdmin(const SwarmNotAdmin& note, std::string& err)
{
    SwarmNotAdminResult result;
    result.moved = false;
    result.height_changed = false;
    // An admin cannot move a sponsor refund key or refund height.
    if (note.admin_id.empty()) {
        result.code = "ADMIN";
        result.moved = false;
        result.height_changed = false;
        err = "ADMIN";
        return result;
    }
    if (note.want_move) {
        result.code = "REFUSED";
        result.moved = false;
        result.height_changed = false;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.height_changed = false;
    err.clear();
    return result;
}

} // namespace modelnet
