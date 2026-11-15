// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoaccounting2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoAccounting2Result SwarmNoteNotNoAccounting2(const SwarmNotNoAccounting2& note, std::string& err)
{
    SwarmNotNoAccounting2Result result;
    result.settled = false;
    result.atoms = 0;
    // Accounting records a balance and settles nothing.
    if (note.ledger_id.empty()) {
        result.code = "LEDGER";
        result.settled = false;
        result.atoms = 0;
        err = "LEDGER";
        return result;
    }
    if (note.want_settle) {
        result.code = "HELD";
        result.settled = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
