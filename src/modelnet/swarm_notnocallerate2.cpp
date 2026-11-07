// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocallerate2.h>

#include <string>

namespace modelnet {

SwarmNotNoCallerRate2Result SwarmNoteNotNoCallerRate2(const SwarmNotNoCallerRate2& note, std::string& err)
{
    SwarmNotNoCallerRate2Result result;
    result.advertised = false;
    // A caller-supplied token rate is not an advertisement.
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.advertised = false;
        err = "ENGINE";
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
