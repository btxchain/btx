// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohostnote2.h>

#include <string>

namespace modelnet {

SwarmNotNoHostNote2Result SwarmNoteNotNoHostNote2(const SwarmNotNoHostNote2& note, std::string& err)
{
    SwarmNotNoHostNote2Result result;
    result.recorded = false;
    // A note that names an operator host is refused.
    if (note.note_id.empty()) {
        result.code = "NOTE";
        result.recorded = false;
        err = "NOTE";
        return result;
    }
    if (note.names_host) {
        result.code = "REFUSED";
        result.recorded = false;
        err = "REFUSED";
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
