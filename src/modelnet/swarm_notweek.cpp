// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notweek.h>

namespace modelnet {

SwarmNotWeekResult SwarmNoteNotWeek(const SwarmNotWeek& note, std::string& err)
{
    SwarmNotWeekResult result;
    result.guaranteed = false;
    result.seconds = 0;
    if (note.window_id.empty()) {
        result.code = "WINDOW";
        result.guaranteed = false;
        result.seconds = 0;
        err = "WINDOW";
        return result;
    }
    if (note.blocks != 6720) {
        result.code = "NOT_GUARANTEE";
        result.guaranteed = false;
        result.seconds = 0;
        err = "NOT_GUARANTEE";
        return result;
    }
    if (note.want_guarantee) {
        result.code = "NOT_GUARANTEE";
        result.guaranteed = false;
        result.seconds = 0;
        err = "NOT_GUARANTEE";
        return result;
    }
    result.code = "NOTED";
    result.guaranteed = false;
    result.seconds = 0;
    err.clear();
    return result;
}

} // namespace modelnet
