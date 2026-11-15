// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofee.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoFeeResult SwarmNoteNotNoFee(const SwarmNotNoFee& note, std::string& err)
{
    SwarmNotNoFeeResult result;
    result.charged = false;
    result.atoms = 0;
    // A forwarder-fee note charges nothing. atoms stays 0.
    if (note.hop_id.empty()) {
        result.code = "HOP";
        result.charged = false;
        result.atoms = 0;
        err = "HOP";
        return result;
    }
    if (note.want_charge) {
        result.code = "NOT_CHARGED";
        result.charged = false;
        result.atoms = 0;
        err = "NOT_CHARGED";
        return result;
    }
    result.code = "NOTED";
    result.charged = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
