// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoadvert2.h>

#include <string>

namespace modelnet {

SwarmNotNoAdvert2Result SwarmNoteNotNoAdvert2(const SwarmNotNoAdvert2& note, std::string& err)
{
    SwarmNotNoAdvert2Result result;
    result.advertised = false;
    // advertised stays false on every path. A caller-supplied token rate
    // is not an advertisement.
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.advertised = false;
        err = "SAMPLE";
        return result;
    }
    if (note.caller_rate) {
        result.code = "NOT_ADVERTISED";
        result.advertised = false;
        err = "NOT_ADVERTISED";
        return result;
    }
    if (note.want_advertise) {
        result.code = "HELD";
        result.advertised = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.advertised = false;
    err.clear();
    return result;
}

} // namespace modelnet
