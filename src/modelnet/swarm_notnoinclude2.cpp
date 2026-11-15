// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoinclude2.h>

namespace modelnet {

SwarmNotNoInclude2Result SwarmNoteNotNoInclude2(const SwarmNotNoInclude2& note, std::string& err)
{
    // An inclusive boundary excludes no member.
    SwarmNotNoInclude2Result result;
    result.excluded = false;
    if (note.set_id.empty()) {
        result.code = "SET";
        result.excluded = false;
        err = "SET";
        return result;
    }
    if (note.inclusive) {
        result.code = "STAYS";
        result.excluded = false;
        err = "STAYS";
        return result;
    }
    if (note.want_exclude) {
        result.code = "HELD";
        result.excluded = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.excluded = false;
    err.clear();
    return result;
}

} // namespace modelnet
