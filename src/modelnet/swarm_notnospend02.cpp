// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospend02.h>

#include <string>
#include <cstdint>

namespace modelnet {

SwarmNotNoSpend02Result SwarmNoteNotNoSpend02(const SwarmNotNoSpend02& note, std::string& err)
{
    SwarmNotNoSpend02Result result;
    result.armed = false;
    result.atoms = 0;
    // Automatic spend stays zero until an operator wallet signs a
    // bounded mandate.
    if (note.wallet_id.empty()) {
        result.code = "WALLET";
        result.armed = false;
        result.atoms = 0;
        err = "WALLET";
        return result;
    }
    if (note.want_arm) {
        result.code = "HELD";
        result.armed = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.armed = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
