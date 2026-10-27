// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreal.h>

namespace modelnet {

SwarmNotNoRealResult SwarmNoteNotNoReal(const SwarmNotNoReal& note, std::string& err)
{
    SwarmNotNoRealResult result;
    result.opened = false;
    result.atoms = 0;
    // A real-money channel is not opened.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.opened = false;
        result.atoms = 0;
        err = "CHANNEL";
        return result;
    }
    if (note.want_open) {
        result.code = "REAL_MONEY";
        result.opened = false;
        result.atoms = 0;
        err = "REAL_MONEY";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
