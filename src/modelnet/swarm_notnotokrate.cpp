// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotokrate.h>

#include <string>

namespace modelnet {

SwarmNotNoTokRateResult SwarmNoteNotNoTokRate(const SwarmNotNoTokRate& note, std::string& err)
{
    SwarmNotNoTokRateResult result;
    result.advertised = false;
    result.qualified = false;
    // advertised and qualified stay false on every path. A caller-supplied
    // token rate does not advertise or qualify an engine.
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.advertised = false;
        result.qualified = false;
        err = "ENGINE";
        return result;
    }
    if (note.caller_rate) {
        result.code = "NOT_ADVERTISED";
        result.advertised = false;
        result.qualified = false;
        err = "NOT_ADVERTISED";
        return result;
    }
    if (note.want_advertise) {
        result.code = "HELD";
        result.advertised = false;
        result.qualified = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.advertised = false;
    result.qualified = false;
    err.clear();
    return result;
}

} // namespace modelnet
