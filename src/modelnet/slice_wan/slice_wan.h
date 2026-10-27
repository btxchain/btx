// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SLICE_WAN_SLICE_WAN_H
#define BITCOIN_MODELNET_SLICE_WAN_SLICE_WAN_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/realm_roles/realm_roles.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One WAN slice on a single RealmRoles object.
 * Seated names, in order: ingress, attestor, controller, mirror-a,
 * mirror-b, endpoint-a, endpoint-b, endpoint-c.
 * This is one object, not eight processes.
 * Pass seats those names, advances sequence 0 then 1, and
 * Hosts(2) returns false with HOSTS.
 * hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * passed(), launched(), gpu(), broadcast(), qualified(), and
 * release_qualified() stay false.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * No socket is opened and no process is started.
 */
class SliceWan {
public:
    bool Pass(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    bool passed() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    int64_t hosts() const { return m_roles.hosts(); }
    int64_t physical_hosts() const { return m_roles.physical_hosts(); }
    int64_t bytes_moved() const { return m_roles.bytes_moved(); }

private:
    RealmRoles m_roles;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SLICE_WAN_SLICE_WAN_H
