// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notautospend.h>

#include <string>

namespace modelnet {

SwarmNotAutospendResult SwarmNoteNotAutospend(const SwarmNotAutospend& note, std::string& err)
{
    SwarmNotAutospendResult result;
    result.spent = false;
    result.broadcast = false;
    // automatic_spend_atoms stays "0" until an operator wallet signs a
    // bounded mandate. This note spends nothing.
    if (note.wallet_id.empty()) {
        result.code = "WALLET";
        result.spent = false;
        result.broadcast = false;
        err = "WALLET";
        return result;
    }
    if (note.automatic_spend_atoms != "0") {
        result.code = "HELD";
        result.spent = false;
        result.broadcast = false;
        err = "HELD";
        return result;
    }
    if (note.want_spend) {
        result.code = "HELD";
        result.spent = false;
        result.broadcast = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.spent = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
