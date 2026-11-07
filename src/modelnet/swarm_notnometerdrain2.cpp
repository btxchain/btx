// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnometerdrain2.h>

#include <string>

namespace modelnet {

SwarmNotNoMeterDrain2Result SwarmNoteNotNoMeterDrain2(const SwarmNotNoMeterDrain2& note, std::string& err)
{
    // On a metered link the governor drains workers to zero.
    SwarmNotNoMeterDrain2Result result;
    result.workers = 0;
    if (note.governor_id.empty()) {
        result.code = "GOVERNOR";
        result.workers = 0;
        err = "GOVERNOR";
        return result;
    }
    // Metered is DRAINED even when want_keep is false.
    if (note.metered) {
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
