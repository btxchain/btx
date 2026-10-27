// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TENANT_H
#define BTX_MODELNET_SWARM_TENANT_H

#include <string>

namespace modelnet {

/**
 * An empty tenant, an empty cache tenant, a different tenant, or an
 * unauthorized caller is TENANT. The error is the same in each case. This
 * function has no output that says whether a page exists. The same tenant
 * with authorization clears err.
 */
bool SwarmLookupTenant(const std::string& tenant, const std::string& cache_tenant, bool authorized, std::string& err);

/**
 * A shared realm key is not a per-recipient rotation (SHARED_REALM_KEY).
 * Otherwise the result is KEY_EPOCH. rotated stays false. This function does
 * not generate key material and does not claim a new key was created.
 */
bool SwarmRotateKeyEpoch(bool shared_realm_key, bool& rotated, std::string& err);

/** This process does not open a public rendezvous socket. */
bool SwarmOpenPublicRendezvous(bool want_socket, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TENANT_H
