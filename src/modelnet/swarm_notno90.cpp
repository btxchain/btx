// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno90.h>

namespace modelnet {

SwarmNotNo90Result SwarmNoteNotNo90(const SwarmNotNo90& note, std::string& err)
{
    SwarmNotNo90Result result;
    result.guaranteed = false;
    result.applied_seconds = 0;
    // A 90-second block target is not a wall-clock guarantee.
    if (note.spacing_id.empty()) {
        result.code = "SPACING";
        result.guaranteed = false;
        result.applied_seconds = 0;
        err = "SPACING";
        return result;
    }
    if (note.seconds != 90) {
        result.code = "NOT_GUARANTEE";
        result.guaranteed = false;
        result.applied_seconds = 0;
        err = "NOT_GUARANTEE";
        return result;
    }
    if (note.want_guarantee) {
        result.code = "NOT_GUARANTEE";
        result.guaranteed = false;
        result.applied_seconds = 0;
        err = "NOT_GUARANTEE";
        return result;
    }
    result.code = "NOTED";
    result.guaranteed = false;
    result.applied_seconds = 0;
    err.clear();
    return result;
}

} // namespace modelnet
