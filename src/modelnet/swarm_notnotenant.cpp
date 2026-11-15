// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotenant.h>

#include <string>

namespace modelnet {

SwarmNotNoTenantResult SwarmNoteNotNoTenant(const SwarmNotNoTenant& note, std::string& err)
{
    SwarmNotNoTenantResult result;
    result.read = false;
    result.bytes_moved = false;
    // A lookup for another tenant reads nothing and moves no bytes.
    // read and bytes_moved stay false on every path.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.read = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    if (note.other_tenant) {
        result.code = "TENANT";
        result.read = false;
        result.bytes_moved = false;
        err = "TENANT";
        return result;
    }
    if (note.want_read) {
        result.code = "HELD";
        result.read = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.read = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
