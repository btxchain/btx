// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopaynet.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoPaynetResult SwarmNoteNotNoPaynet(const SwarmNotNoPaynet& note, std::string& err)
{
    SwarmNotNoPaynetResult result;
    result.broadcast = false;
    result.atoms = 0;
    // An accounting-only paynet broadcasts nothing. atoms stays 0.
    if (note.ledger_id.empty()) {
        result.code = "LEDGER";
        result.broadcast = false;
        result.atoms = 0;
        err = "LEDGER";
        return result;
    }
    if (note.want_broadcast) {
        result.code = "NOT_BROADCAST";
        result.broadcast = false;
        result.atoms = 0;
        err = "NOT_BROADCAST";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
