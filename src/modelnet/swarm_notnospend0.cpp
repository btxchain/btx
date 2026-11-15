// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospend0.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoSpend0Result SwarmNoteNotNoSpend0(const SwarmNotNoSpend0& note, std::string& err)
{
    SwarmNotNoSpend0Result result;
    result.spent = false;
    result.atoms = 0;
    // automatic_spend_atoms stays 0 until a wallet signs a bounded
    // mandate, and this note spends nothing.
    if (note.mandate_id.empty()) {
        result.code = "MANDATE";
        result.spent = false;
        result.atoms = 0;
        err = "MANDATE";
        return result;
    }
    if (note.spend_atoms != 0) {
        result.code = "HELD";
        result.spent = false;
        result.atoms = 0;
        err = "HELD";
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
