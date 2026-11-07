// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohflineage2.h>

namespace modelnet {

SwarmNotNoHfLineage2Result SwarmNoteNotNoHfLineage2(const SwarmNotNoHfLineage2& note, std::string& err)
{
    // A hub model card is not lineage authority.
    SwarmNotNoHfLineage2Result result;
    if (note.model_id.empty()) {
        result.code = "MODEL";
        result.trusted = false;
        err = "MODEL";
        return result;
    }
    if (note.hub_card) {
        result.code = "NOT_LINEAGE";
        result.trusted = false;
        err = "NOT_LINEAGE";
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
