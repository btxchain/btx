// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolineage.h>

namespace modelnet {

SwarmNotNoLineageResult SwarmNoteNotNoLineage(const SwarmNotNoLineage& note, std::string& err)
{
    // A hub listing is not lineage authority and publishes nothing.
    SwarmNotNoLineageResult result;
    if (note.model_id.empty()) {
        result.code = "MODEL";
        result.authority = false;
        result.published = false;
        err = "MODEL";
        return result;
    }
    if (note.want_authority) {
        result.code = "NOT_AUTHORITY";
        result.authority = false;
        result.published = false;
        err = "NOT_AUTHORITY";
        return result;
    }
    result.code = "NOTED";
    result.authority = false;
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
