// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnothermdrain2.h>

#include <string>

namespace modelnet {

SwarmNotNoThermDrain2Result SwarmNoteNotNoThermDrain2(const SwarmNotNoThermDrain2& note, std::string& err)
{
    // On thermal limit the governor drains workers to zero.
    SwarmNotNoThermDrain2Result result;
    result.workers = 0;
    if (note.governor_id.empty()) {
        result.code = "GOVERNOR";
        result.workers = 0;
        err = "GOVERNOR";
        return result;
    }
    // Thermal is DRAINED even when want_keep is false.
    if (note.thermal) {
        result.code = "DRAINED";
        result.workers = 0;
        err = "DRAINED";
        return result;
    }
    if (note.want_keep) {
        result.code = "HELD";
        result.workers = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.workers = 0;
    err.clear();
    return result;
}

} // namespace modelnet
