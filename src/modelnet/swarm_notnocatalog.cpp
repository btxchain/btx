// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocatalog.h>

#include <string>

namespace modelnet {

SwarmNotNoCatalogResult SwarmNoteNotNoCatalog(const SwarmNotNoCatalog& note, std::string& err)
{
    SwarmNotNoCatalogResult result;
    result.authority = false;
    result.published = false;
    // A catalog entry is not lineage authority.
    if (note.entry_id.empty()) {
        result.code = "ENTRY";
        result.authority = false;
        result.published = false;
        err = "ENTRY";
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
