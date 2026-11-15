// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnokwh.h>

#include <string>

namespace modelnet {

SwarmNotNoKwhResult SwarmNoteNotNoKwh(const SwarmNotNoKwh& note, std::string& err)
{
    SwarmNotNoKwhResult result;
    result.published = false;
    result.milliwatt_hours = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.milliwatt_hours = 0;
        err = "RUN";
        return result;
    }
    // This note publishes no energy figure.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.milliwatt_hours = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.milliwatt_hours = 0;
    err.clear();
    return result;
}

} // namespace modelnet
