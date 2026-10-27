// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradexport.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmGradExportResult SwarmNoteGradExport(const SwarmGradExport& update, std::string& err)
{
    // A gradient update is not exported.
    SwarmGradExportResult result;
    result.exported = false;
    result.bytes_moved = 0;
    if (update.update_id.empty()) {
        result.code = "UPDATE";
        result.exported = false;
        result.bytes_moved = 0;
        err = "UPDATE";
        return result;
    }
    if (update.gradient) {
        result.code = "NOT_EXPORTED";
        result.exported = false;
        result.bytes_moved = 0;
        err = "NOT_EXPORTED";
        return result;
    }
    if (update.want_export) {
        result.code = "HELD";
        result.exported = false;
        result.bytes_moved = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.exported = false;
    result.bytes_moved = 0;
    err.clear();
    return result;
}

} // namespace modelnet
