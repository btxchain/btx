// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoimmature.h>

#include <string>

namespace modelnet {

SwarmNotNoImmatureResult SwarmNoteNotNoImmature(const SwarmNotNoImmature& note, std::string& err)
{
    SwarmNotNoImmatureResult result;
    result.paid = false;
    result.atoms = 0;
    if (note.refund_id.empty()) {
        result.code = "REFUND";
        result.paid = false;
        result.atoms = 0;
        err = "REFUND";
        return result;
    }
    // An immature refund pays nothing.
    if (note.immature) {
        result.code = "NOT_PAID";
        result.paid = false;
        result.atoms = 0;
        err = "NOT_PAID";
        return result;
    }
    if (note.want_pay) {
        result.code = "HELD";
        result.paid = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
