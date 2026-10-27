// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnounfunded.h>

#include <string>

namespace modelnet {

SwarmNotNoUnfundedResult SwarmNoteNotNoUnfunded(const SwarmNotNoUnfunded& note, std::string& err)
{
    SwarmNotNoUnfundedResult result;
    result.advertised = false;
    result.atoms = 0;
    // advertised stays false and atoms stays 0 on every path. An
    // unfunded pool is not advertised as holding money.
    if (note.pool_id.empty()) {
        result.code = "POOL";
        result.advertised = false;
        result.atoms = 0;
        err = "POOL";
        return result;
    }
    if (note.unfunded) {
        result.code = "NOT_HELD";
        result.advertised = false;
        result.atoms = 0;
        err = "NOT_HELD";
        return result;
    }
    if (note.want_advertise) {
        result.code = "HELD";
        result.advertised = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.advertised = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
