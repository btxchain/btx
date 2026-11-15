// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofourbal2.h>

#include <string>

namespace modelnet {

SwarmNotNoFourBal2Result SwarmNoteNotNoFourBal2(const SwarmNotNoFourBal2& note, std::string& err)
{
    SwarmNotNoFourBal2Result result;
    result.merged = false;
    // Four balances stay separate.
    if (note.ledger_id.empty()) {
        result.code = "LEDGER";
        result.merged = false;
        err = "LEDGER";
        return result;
    }
    if (note.want_merge) {
        result.code = "HELD";
        result.merged = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.merged = false;
    err.clear();
    return result;
}

} // namespace modelnet
