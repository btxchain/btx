// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospend.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoSpendResult SwarmNoteNotNoSpend(const SwarmNotNoSpend& note, std::string& err)
{
    SwarmNotNoSpendResult result;
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
    if (!note.signed_by_wallet) {
        result.code = "UNSIGNED";
        result.spent = false;
        result.atoms = 0;
        err = "UNSIGNED";
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
