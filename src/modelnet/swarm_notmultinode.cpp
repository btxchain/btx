// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmultinode.h>

namespace modelnet {

SwarmNotMultiNodeResult SwarmNoteNotMultiNode(const SwarmNotMultiNode& note, std::string& err)
{
    // Publication never happens. paired stays false. tokens_per_sec stays 0.
    SwarmNotMultiNodeResult out;
    out.published = false;
    out.paired = false;
    out.tokens_per_sec = 0;

    if (note.run_id.empty()) {
        out.code = "NODE";
        err = "NODE";
        return out;
    }
    if (note.want_publish) {
        out.code = "OUT_OF_SCOPE";
        err = "OUT_OF_SCOPE";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
