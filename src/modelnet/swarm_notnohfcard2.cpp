// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohfcard2.h>

namespace modelnet {

SwarmNotNoHfCard2Result SwarmNoteNotNoHfCard2(const SwarmNotNoHfCard2& note, std::string& err)
{
    // A hub card is not lineage authority.
    SwarmNotNoHfCard2Result result;
    if (note.card_id.empty()) {
        result.code = "CARD";
        result.trusted = false;
        err = "CARD";
        return result;
    }
    if (note.want_trust) {
        result.code = "HELD";
        result.trusted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.trusted = false;
    err.clear();
    return result;
}

} // namespace modelnet
