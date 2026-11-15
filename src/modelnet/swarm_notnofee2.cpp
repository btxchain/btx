// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofee2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoFee2Result SwarmNoteNotNoFee2(const SwarmNotNoFee2& note, std::string& err)
{
    SwarmNotNoFee2Result result;
    result.charged = false;
    result.atoms = 0;
    // The formula base + (amount*ppm+999999)/1000000 is not applied.
    // A forwarder fee is not charged. atoms stays 0.
    if (note.edge_id.empty()) {
        result.code = "EDGE";
        result.charged = false;
        result.atoms = 0;
        err = "EDGE";
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
