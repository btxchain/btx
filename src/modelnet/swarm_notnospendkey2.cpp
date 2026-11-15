// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospendkey2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoSpendKey2Result SwarmNoteNotNoSpendKey2(const SwarmNotNoSpendKey2& note, std::string& err)
{
    SwarmNotNoSpendKey2Result result;
    result.armed = false;
    result.atoms = 0;
    if (note.key_id.empty()) {
        result.code = "KEY";
        result.armed = false;
        result.atoms = 0;
        err = "KEY";
        return result;
    }
    // A research key is not a spend key.
    if (note.research) {
        result.code = "NOT_SPEND";
        result.armed = false;
        result.atoms = 0;
        err = "NOT_SPEND";
        return result;
    }
    if (note.want_arm) {
        result.code = "HELD";
        result.armed = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.armed = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
