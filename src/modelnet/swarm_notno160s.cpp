// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno160s.h>

namespace modelnet {

SwarmNotNo160sResult SwarmNoteNotNo160s(const SwarmNotNo160s& note, std::string& err)
{
    SwarmNotNo160sResult result;
    result.guaranteed = false;
    result.applied_seconds = 0;
    if (note.clock_id.empty()) {
        result.code = "CLOCK";
        result.guaranteed = false;
        result.applied_seconds = 0;
        err = "CLOCK";
        return result;
    }
    if (note.blocks != 160) {
        result.code = "NOT_GUARANTEE";
        result.guaranteed = false;
        result.applied_seconds = 0;
        err = "NOT_GUARANTEE";
        return result;
    }
    if (note.want_wallclock) {
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
