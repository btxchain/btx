// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoidremap.h>

#include <string>

namespace modelnet {

SwarmNotNoIdRemapResult SwarmNoteNotNoIdRemap(const SwarmNotNoIdRemap& note, std::string& err)
{
    SwarmNotNoIdRemapResult result;
    result.remapped = false;
    result.spent = false;
    // A compromised key is not remapped onto a spend path and spends
    // nothing. remapped and spent stay false on every path.
    if (note.key_id.empty()) {
        result.code = "KEY";
        result.remapped = false;
        result.spent = false;
        err = "KEY";
        return result;
    }
    if (note.compromised) {
        result.code = "IDENTITY_REMAP";
        result.remapped = false;
        result.spent = false;
        err = "IDENTITY_REMAP";
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
