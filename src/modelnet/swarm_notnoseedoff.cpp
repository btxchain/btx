// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseedoff.h>

#include <string>

namespace modelnet {

SwarmNotNoSeedOffResult SwarmNoteNotNoSeedOff(const SwarmNotNoSeedOff& note, std::string& err)
{
    SwarmNotNoSeedOffResult result;
    result.published = false;
    result.authority = false;
    // An empty seed list is not an authority publish.
    if (note.seed_id.empty()) {
        result.code = "SEED";
        result.published = false;
        result.authority = false;
        err = "SEED";
        return result;
    }
    if (note.want_publish) {
        result.code = "NOT_AUTHORITY";
        result.published = false;
        result.authority = false;
        err = "NOT_AUTHORITY";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.authority = false;
    err.clear();
    return result;
}

} // namespace modelnet
