// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.

#include <modelnet/swarm_tenantlook.h>

#include <string>

namespace modelnet {

SwarmTenantLookResult SwarmLookupTenantAccess(const SwarmTenantLook& look, std::string& err)
{
    // A tenant lookup grants nothing from this record and moves no bytes.
    SwarmTenantLookResult result;
    result.allowed = false;
    result.bytes_moved = false;
    if (look.tenant_id.empty()) {
        result.code = "TENANT";
        result.allowed = false;
        result.bytes_moved = false;
        err = "TENANT";
        return result;
    }
    if (look.caller_id.empty()) {
        result.code = "CALLER";
        result.allowed = false;
        result.bytes_moved = false;
        err = "CALLER";
        return result;
    }
    if (look.caller_id != look.tenant_id) {
        result.code = "TENANT";
        result.allowed = false;
        result.bytes_moved = false;
        err = "TENANT";
        return result;
    }
    if (look.revoked) {
        result.code = "REVOKED";
        result.allowed = false;
        result.bytes_moved = false;
        err = "REVOKED";
        return result;
    }
    if (look.want_read) {
        result.code = "HELD";
        result.allowed = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.allowed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
