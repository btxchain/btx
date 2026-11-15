// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nothflineage.h>

namespace modelnet {

SwarmNotHfLineageResult SwarmNoteNotHfLineage(const SwarmNotHfLineage& note, std::string& err)
{
    // A Hugging Face import origin is not lineage authority and
    // publish-back is not authority. This note publishes nothing.
    SwarmNotHfLineageResult result;
    if (note.origin_id.empty()) {
        result.code = "ORIGIN";
        result.authority = false;
        result.published = false;
        err = "ORIGIN";
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
