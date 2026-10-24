// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobalance.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoBalanceResult SwarmNoteNotNoBalance(const SwarmNotNoBalance& note, std::string& err)
{
    SwarmNotNoBalanceResult result;
    result.combined = false;
    result.atoms = 0;
    // The four balances stay separate.
    if (note.ledger_id.empty()) {
        result.code = "LEDGER";
        result.combined = false;
        result.atoms = 0;
        err = "LEDGER";
        return result;
    }
    if (note.mixed_books) {
        result.code = "SEPARATE";
        result.combined = false;
        result.atoms = 0;
        err = "SEPARATE";
        return result;
    }
    if (note.want_combine) {
        result.code = "HELD";
        result.combined = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.combined = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
