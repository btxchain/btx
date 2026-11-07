// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofee0.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoFee0Result SwarmNoteNotNoFee0(const SwarmNotNoFee0& note, std::string& err)
{
    SwarmNotNoFee0Result result;
    result.charged = false;
    result.atoms = 0;
    // A forwarder fee is not charged by this note. atoms stays 0.
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
