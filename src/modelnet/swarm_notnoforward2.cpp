// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoforward2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoForward2Result SwarmNoteNotNoForward2(const SwarmNotNoForward2& note, std::string& err)
{
    SwarmNotNoForward2Result result;
    result.charged = false;
    result.atoms = 0;
    // A forwarder fee is not charged.
    if (note.hop_id.empty()) {
        result.code = "HOP";
        result.charged = false;
        result.atoms = 0;
        err = "HOP";
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
