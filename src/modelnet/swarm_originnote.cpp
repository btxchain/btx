// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_originnote.h>

namespace modelnet {

SwarmImportOriginResult SwarmNoteImportOrigin(const SwarmImportOrigin& origin, std::string& err)
{
    SwarmImportOriginResult result;
    result.lineage_authority = false;
    if (origin.url.empty()) {
        result.code = "ORIGIN";
        err = "ORIGIN";
        return result;
    }
    // An import or publish-back origin is not lineage authority.
    // NOT_AUTHORITY wins even when import_origin is true.
    if (origin.want_lineage) {
        result.code = "NOT_AUTHORITY";
        err = "NOT_AUTHORITY";
        return result;
    }
    result.code = "NOTED";
    result.lineage_authority = false;
    err.clear();
    return result;
}

} // namespace modelnet
