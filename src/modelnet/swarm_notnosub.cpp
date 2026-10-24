// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosub.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoSubResult SwarmNoteNotNoSub(const SwarmNotNoSub& note, std::string& err)
{
    SwarmNotNoSubResult result;
    result.charged = false;
    result.atoms = 0;
    // A subscription note charges nothing.
    if (note.sub_id.empty()) {
        result.code = "SUB";
        result.charged = false;
        result.atoms = 0;
        err = "SUB";
        return result;
    }
    if (note.want_charge) {
        result.code = "NOT_CHARGED";
        result.charged = false;
        result.atoms = 0;
        err = "NOT_CHARGED";
        return result;
    }
    result.code = "NOTED";
    result.charged = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
