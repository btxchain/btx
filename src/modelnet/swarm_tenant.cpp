// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tenant.h>

namespace modelnet {

bool SwarmLookupTenant(const std::string& tenant, const std::string& cache_tenant, bool authorized, std::string& err)
{
    if (tenant.empty() || cache_tenant.empty() || tenant != cache_tenant || !authorized) {
        err = "TENANT";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmRotateKeyEpoch(bool shared_realm_key, bool& rotated, std::string& err)
{
    rotated = false;
    if (shared_realm_key) {
        err = "SHARED_REALM_KEY";
        return false;
    }
    err = "KEY_EPOCH";
    return false;
}

bool SwarmOpenPublicRendezvous(bool want_socket, std::string& err)
{
    if (want_socket) {
        err = "NO_SOCKET";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
