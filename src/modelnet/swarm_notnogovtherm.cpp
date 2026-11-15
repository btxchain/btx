// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogovtherm.h>

#include <string>

namespace modelnet {

SwarmNotNoGovThermResult SwarmNoteNotNoGovTherm(const SwarmNotNoGovTherm& note, std::string& err)
{
    // The governor drains workers to zero on thermal. This note starts none.
    SwarmNotNoGovThermResult result;
    result.running = false;
    result.workers = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.running = false;
        result.workers = 0;
        err = "NODE";
        return result;
    }
    // thermal is ZERO even when want_run is false.
    if (note.thermal) {
        result.code = "ZERO";
        result.running = false;
        result.workers = 0;
        err = "ZERO";
        return result;
    }
    if (note.want_run) {
        result.code = "HELD";
        result.running = false;
        result.workers = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.running = false;
    result.workers = 0;
    err.clear();
    return result;
}

} // namespace modelnet
