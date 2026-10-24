// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofwdfee2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoFwdFee2Result SwarmNoteNotNoFwdFee2(const SwarmNotNoFwdFee2& note, std::string& err)
{
    SwarmNotNoFwdFee2Result result;
    result.charged = false;
    result.atoms = 0;
    // A forwarder fee is not charged.
    if (note.edge_id.empty()) {
        result.code = "EDGE";
        result.charged = false;
        result.atoms = 0;
        err = "EDGE";
        return result;
    }
    if (note.forwarder) {
        result.code = "NOT_CHARGED";
        result.charged = false;
        result.atoms = 0;
        err = "NOT_CHARGED";
        return result;
    }
    if (note.want_charge) {
        result.code = "HELD";
        result.charged = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.charged = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
