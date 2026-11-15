// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopin.h>

#include <string>

namespace modelnet {

SwarmNotNoPinResult SwarmNoteNotNoPin(const SwarmNotNoPin& note, std::string& err)
{
    SwarmNotNoPinResult result;
    result.seeded = false;
    result.published = false;
    // Pin membership is not a public seed authority.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.seeded = false;
        result.published = false;
        err = "NODE";
        return result;
    }
    if (note.pin_member) {
        result.code = "NOT_SEED";
        result.seeded = false;
        result.published = false;
        err = "NOT_SEED";
        return result;
    }
    if (note.want_seed) {
        result.code = "HELD";
        result.seeded = false;
        result.published = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.seeded = false;
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
