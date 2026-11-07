// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorefundmat.h>

#include <string>

namespace modelnet {

SwarmNotNoRefundMatResult SwarmNoteNotNoRefundMat(const SwarmNotNoRefundMat& note, std::string& err)
{
    SwarmNotNoRefundMatResult result;
    result.refunded = false;
    result.atoms = 0;
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.refunded = false;
        result.atoms = 0;
        err = "CHANNEL";
        return result;
    }
    // An immature refund pays nothing.
    if (!note.mature) {
        result.code = "NOT_MATURE";
        result.refunded = false;
        result.atoms = 0;
        err = "NOT_MATURE";
        return result;
    }
    if (note.want_refund) {
        result.code = "HELD";
        result.refunded = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.refunded = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
