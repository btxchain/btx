// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notwear.h>

namespace modelnet {

SwarmNotWearResult SwarmNoteNotWear(const SwarmNotWear& note, std::string& err)
{
    // Publication never happens. wear stays 0. This note does not read hardware wear.
    SwarmNotWearResult out;
    out.published = false;
    out.wear = 0;

    if (note.device_id.empty()) {
        out.code = "DEVICE";
        err = "DEVICE";
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
