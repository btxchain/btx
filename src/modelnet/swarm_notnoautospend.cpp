// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoautospend.h>

#include <string>
#include <cstdint>

namespace modelnet {

SwarmNotNoAutoSpendResult SwarmNoteNotNoAutoSpend(const SwarmNotNoAutoSpend& note, std::string& err)
{
    SwarmNotNoAutoSpendResult result;
    result.armed = false;
    result.atoms = 0;
    // automatic_spend_atoms stays zero until an operator wallet signs a
    // bounded mandate. This note arms nothing.
    if (note.mandate_id.empty()) {
        result.code = "MANDATE";
        result.armed = false;
        result.atoms = 0;
        err = "MANDATE";
        return result;
    }
    if (note.want_arm) {
        result.code = "ZERO";
        result.armed = false;
        result.atoms = 0;
        err = "ZERO";
        return result;
    }
    result.code = "NOTED";
    result.armed = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
