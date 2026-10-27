// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.

#ifndef BTX_MODELNET_SWARM_TENANTLOOK_H
#define BTX_MODELNET_SWARM_TENANTLOOK_H

#include <string>

namespace modelnet {

/**
 * A tenant lookup. tenant_id names the record. caller_id is who asks.
 * revoked marks the record closed. want_read asks this record to read.
 *
 * A tenant lookup grants nothing from this record and moves no bytes,
 * so allowed stays false and bytes_moved stays false on every path.
 */
struct SwarmTenantLook {
    std::string tenant_id;
    std::string caller_id;
    bool revoked{false};
    bool want_read{false};
};

/**
 * Outcome of a tenant lookup. allowed stays false and bytes_moved
 * stays false on every path. A tenant lookup grants nothing from this
 * record and moves no bytes.
 */
struct SwarmTenantLookResult {
    std::string code;
    bool allowed{false};
    bool bytes_moved{false};
};

/**
 * Look up tenant access without reading the record or moving bytes.
 * The caller matches only when both ids are non-empty and equal.
 * Order, first match wins: an empty tenant_id is TENANT. An empty
 * caller_id is CALLER, checked before the inequality. A caller_id
 * that differs from tenant_id is TENANT. revoked is REVOKED, even
 * when want_read is false. want_read is HELD. Otherwise the lookup
 * is NOTED and err is cleared. allowed stays false and bytes_moved
 * stays false on every path.
 * A tenant lookup grants nothing from this record and moves no bytes.
 */
SwarmTenantLookResult SwarmLookupTenantAccess(const SwarmTenantLook& look, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TENANTLOOK_H
