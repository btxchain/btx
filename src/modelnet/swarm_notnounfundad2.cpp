// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnounfundad2.h>

namespace modelnet {

// An unfunded pool is not advertised as holding money.
SwarmNotNoUnfundAd2Result SwarmNoteNotNoUnfundAd2(const SwarmNotNoUnfundAd2& note, std::string& err)
{
    SwarmNotNoUnfundAd2Result result;
    result.advertised = false;
    result.atoms = 0;
    if (note.pool_id.empty()) {
        result.code = "POOL";
        err = "POOL";
        return result;
    }
    if (note.unfunded) {
        result.code = "NOT_ADVERTISED";
        err = "NOT_ADVERTISED";
        return result;
    }
    if (note.want_advertise) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
