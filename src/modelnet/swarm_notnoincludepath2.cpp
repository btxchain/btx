// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.

#include <modelnet/swarm_notnoincludepath2.h>

namespace modelnet {

SwarmNotNoIncludePath2Result SwarmNoteNotNoIncludePath2(const SwarmNotNoIncludePath2& note, std::string& err)
{
    // A unit note records no include path.
    SwarmNotNoIncludePath2Result result;
    result.recorded = false;
    if (note.note_id.empty()) {
        result.code = "NOTE";
        result.recorded = false;
        err = "NOTE";
        return result;
    }
    if (note.want_record) {
        result.code = "HELD";
        result.recorded = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.recorded = false;
    err.clear();
    return result;
}

} // namespace modelnet
