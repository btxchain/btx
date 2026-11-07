// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnointeger2.h>

#include <string>

namespace modelnet {

SwarmNotNoInteger2Result SwarmNoteNotNoInteger2(const SwarmNotNoInteger2& note, std::string& err)
{
    SwarmNotNoInteger2Result result;
    result.added = false;
    result.pairs = 0;
    // INTEGER_LINEAR stays eight frozen pairs. This note adds none.
    if (note.pair_id.empty()) {
        result.code = "PAIR";
        result.added = false;
        result.pairs = 0;
        err = "PAIR";
        return result;
    }
    if (note.want_add) {
        result.code = "HELD";
        result.added = false;
        result.pairs = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    result.pairs = 0;
    err.clear();
    return result;
}

} // namespace modelnet
