// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfourbal.h>

#include <string>

namespace modelnet {

SwarmNotFourBalResult SwarmNoteNotFourBal(const SwarmNotFourBal& note, std::string& err)
{
    SwarmNotFourBalResult result;
    result.merged = false;
    // The four balances stay separate.
    if (note.ledger_id.empty()) {
        result.code = "LEDGER";
        result.merged = false;
        err = "LEDGER";
        return result;
    }
    if (note.want_merge) {
        result.code = "SEPARATE";
        result.merged = false;
        err = "SEPARATE";
        return result;
    }
    result.code = "NOTED";
    result.merged = false;
    err.clear();
    return result;
}

} // namespace modelnet
