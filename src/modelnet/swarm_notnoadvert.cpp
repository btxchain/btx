// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoadvert.h>

#include <string>

namespace modelnet {

SwarmNotNoAdvertResult SwarmNoteNotNoAdvert(const SwarmNotNoAdvert& note, std::string& err)
{
    SwarmNotNoAdvertResult result;
    result.advertised = false;
    result.qualified = false;
    // advertised and qualified stay false on every path. A caller-supplied
    // token rate does not advertise or qualify an engine and starts nothing.
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.advertised = false;
        result.qualified = false;
        err = "ENGINE";
        return result;
    }
    if (note.caller_rate) {
        result.code = "UNMEASURED";
        result.advertised = false;
        result.qualified = false;
        err = "UNMEASURED";
        return result;
    }
    if (note.want_advertise) {
        result.code = "UNMEASURED";
        result.advertised = false;
        result.qualified = false;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.advertised = false;
    result.qualified = false;
    err.clear();
    return result;
}

} // namespace modelnet
