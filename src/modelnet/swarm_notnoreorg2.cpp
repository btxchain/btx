// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreorg2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoReorg2Result SwarmNoteNotNoReorg2(const SwarmNotNoReorg2& note, std::string& err)
{
    SwarmNotNoReorg2Result result;
    result.spent = false;
    result.atoms = 0;
    // A reorg freezes the spend and pays nothing.
    if (note.tx_id.empty()) {
        result.code = "TX";
        result.spent = false;
        result.atoms = 0;
        err = "TX";
        return result;
    }
    if (note.reorg) {
        result.code = "FROZEN";
        result.spent = false;
        result.atoms = 0;
        err = "FROZEN";
        return result;
    }
    if (note.want_spend) {
        result.code = "HELD";
        result.spent = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.spent = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
