// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_assumedclose.h>

#include <cstdint>

namespace modelnet {

SwarmAssumedCloseResult SwarmNoteAssumedClose(const SwarmAssumedClose& note, std::string& err)
{
    SwarmAssumedCloseResult result;
    // An 8000-byte close size is an assumption, not a measurement.
    // This note does not measure and does not broadcast.
    result.measured = false;
    result.broadcast = false;
    if (note.channel_id.empty() || note.assumed_bytes < 0) {
        result.code = "SIZE";
        result.measured = false;
        result.broadcast = false;
        err = "SIZE";
        return result;
    }
    if (note.want_measure) {
        result.code = "MEASURE_REFUSED";
        result.measured = false;
        result.broadcast = false;
        err = "MEASURE_REFUSED";
        return result;
    }
    if (note.assumed_bytes != 8000) {
        result.code = "ASSUMPTION";
        result.measured = false;
        result.broadcast = false;
        err = "ASSUMPTION";
        return result;
    }
    result.code = "NOTED";
    result.measured = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
