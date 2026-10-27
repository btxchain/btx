// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrefundleaf.h>

#include <string>

namespace modelnet {

SwarmNotRefundLeafResult SwarmNoteNotRefundLeaf(const SwarmNotRefundLeaf& note, std::string& err)
{
    SwarmNotRefundLeafResult result;
    result.built = false;
    result.broadcast = false;
    // A refund leaf is not built or broadcast by this note.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.built = false;
        result.broadcast = false;
        err = "CHANNEL";
        return result;
    }
    if (note.want_refund) {
        result.code = "HELD";
        result.built = false;
        result.broadcast = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.built = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
