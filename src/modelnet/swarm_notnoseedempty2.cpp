// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseedempty2.h>

#include <string>

namespace modelnet {

SwarmNotNoSeedEmpty2Result SwarmNoteNotNoSeedEmpty2(const SwarmNotNoSeedEmpty2& note, std::string& err)
{
    SwarmNotNoSeedEmpty2Result result;
    result.added = false;
    // The DNS seed list stays empty.
    if (note.list_id.empty()) {
        result.code = "LIST";
        result.added = false;
        err = "LIST";
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
