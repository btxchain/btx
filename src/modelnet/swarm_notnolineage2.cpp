// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolineage2.h>

namespace modelnet {

SwarmNotNoLineage2Result SwarmNoteNotNoLineage2(const SwarmNotNoLineage2& note, std::string& err)
{
    // A hub listing is not lineage authority.
    SwarmNotNoLineage2Result result;
    if (note.model_id.empty()) {
        result.code = "MODEL";
        result.authority = false;
        result.admitted = false;
        err = "MODEL";
        return result;
    }
    if (note.hub_listing) {
        result.code = "NOT_AUTHORITY";
        result.authority = false;
        result.admitted = false;
        err = "NOT_AUTHORITY";
        return result;
    }
    if (note.want_authority) {
        result.code = "HELD";
        result.authority = false;
        result.admitted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.authority = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
