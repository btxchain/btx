// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodnsseed2.h>

#include <string>

namespace modelnet {

SwarmNotNoDnsSeed2Result SwarmNoteNotNoDnsSeed2(const SwarmNotNoDnsSeed2& note, std::string& err)
{
    SwarmNotNoDnsSeed2Result result;
    result.added = false;
    // The DNS seed list stays empty.
    if (note.seed_id.empty()) {
        result.code = "SEED";
        result.added = false;
        err = "SEED";
        return result;
    }
    if (note.want_add) {
        result.code = "HELD";
        result.added = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    err.clear();
    return result;
}

} // namespace modelnet
