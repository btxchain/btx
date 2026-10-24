// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_revokegate.h>

namespace modelnet {

SwarmRevokeGateResult SwarmReadAfterRevoke(bool member_revoked, bool previously_delivered, bool same_tenant,
                                           bool authorized, std::string& err)
{
    SwarmRevokeGateResult result;
    result.plaintext_erased = false;
    result.bytes_moved = false;
    if (previously_delivered) {
        result.allowed = false;
        result.code = "DELIVERED_KEPT";
        err.clear();
        return result;
    }
    if (member_revoked) {
        result.allowed = false;
        result.code = "REVOKED";
        err = "REVOKED";
        return result;
    }
    if (!same_tenant || !authorized) {
        result.allowed = false;
        result.code = "TENANT";
        err = "TENANT";
        return result;
    }
    result.allowed = true;
    result.code = "OK";
    err.clear();
    return result;
}

} // namespace modelnet
