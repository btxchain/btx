// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnokeymap.h>

#include <string>

namespace modelnet {

SwarmNotNoKeyMapResult SwarmNoteNotNoKeyMap(const SwarmNotNoKeyMap& note, std::string& err)
{
    SwarmNotNoKeyMapResult result;
    result.remapped = false;
    result.spent = false;
    // A compromised key is not remapped onto a spend path. remapped
    // and spent stay false on every path.
    if (note.key_id.empty()) {
        result.code = "KEY";
        result.remapped = false;
        result.spent = false;
        err = "KEY";
        return result;
    }
    if (note.compromised) {
        result.code = "NOT_REMAPPED";
        result.remapped = false;
        result.spent = false;
        err = "NOT_REMAPPED";
        return result;
    }
    if (note.want_remap) {
        result.code = "HELD";
        result.remapped = false;
        result.spent = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.remapped = false;
    result.spent = false;
    err.clear();
    return result;
}

} // namespace modelnet
