// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofour2.h>

namespace modelnet {

SwarmNotNoFour2Result SwarmNoteNotNoFour2(const SwarmNotNoFour2& note, std::string& err)
{
    SwarmNotNoFour2Result result;
    result.merged = false;
    result.atoms = 0;
    // Four balances stay separate. This note merges nothing.
    if (note.ledger_id.empty()) {
        result.code = "LEDGER";
        result.merged = false;
        result.atoms = 0;
        err = "LEDGER";
        return result;
    }
    if (note.want_merge) {
        result.code = "HELD";
        result.merged = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.merged = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
