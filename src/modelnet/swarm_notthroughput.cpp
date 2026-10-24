// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notthroughput.h>

namespace modelnet {

SwarmNotThroughputResult SwarmNoteNotThroughput(const SwarmNotThroughput& note, std::string& err)
{
    SwarmNotThroughputResult out;
    out.published = false;
    out.payments_per_sec = 0;
    out.broadcast = false;

    if (note.batch_id.empty()) {
        out.code = "BATCH";
        err = "BATCH";
        return out;
    }
    if (note.want_publish) {
        out.code = "UNMEASURED";
        err = "UNMEASURED";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
