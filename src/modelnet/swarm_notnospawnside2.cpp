// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospawnside2.h>

#include <string>

namespace modelnet {

SwarmNotNoSpawnSide2Result SwarmNoteNotNoSpawnSide2(const SwarmNotNoSpawnSide2& note, std::string& err)
{
    SwarmNotNoSpawnSide2Result result;
    result.spawned = false;
    // btxd does not spawn a sidecar process.
    if (note.name_id.empty()) {
        result.code = "NAME";
        result.spawned = false;
        err = "NAME";
        return result;
    }
    if (note.want_spawn) {
        result.code = "HELD";
        result.spawned = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.spawned = false;
    err.clear();
    return result;
}

} // namespace modelnet
