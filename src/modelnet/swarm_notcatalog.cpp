// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcatalog.h>

#include <string>

namespace modelnet {

SwarmNotCatalogResult SwarmNoteNotCatalog(const SwarmNotCatalog& note, std::string& err)
{
    SwarmNotCatalogResult result;
    result.emitted = false;
    // A model has not been emitted into the catalog.
    if (note.model_id.empty()) {
        result.code = "MODEL";
        result.emitted = false;
        err = "MODEL";
        return result;
    }
    if (note.want_emit) {
        result.code = "NOT_EMITTED";
        result.emitted = false;
        err = "NOT_EMITTED";
        return result;
    }
    result.code = "NOTED";
    result.emitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
