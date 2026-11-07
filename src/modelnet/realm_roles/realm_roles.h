// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_REALM_ROLES_REALM_ROLES_H
#define BITCOIN_MODELNET_REALM_ROLES_REALM_ROLES_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Role names held by one process. It is not six machines.
 *
 * The names are ingress, attestor, controller, mirror-a, mirror-b,
 * endpoint-a, endpoint-b, and endpoint-c.
 *
 * Seat: an empty or unknown role returns ROLE and stores nothing.
 * A known role is stored in the seated set and the live set.
 * hosts() and physical_hosts() stay 1.
 * Hosts: n other than 1 returns HOSTS.
 * Advance: the first sequence is 0. After that the next sequence is
 * exactly last+1. A sequence above that step returns GAP. A lower
 * sequence returns ROLLBACK and keeps the last sequence. An equal
 * sequence returns STALE and keeps the last sequence. A first sequence
 * below 0 returns ROLLBACK and stores nothing.
 * Stop removes that role from the live set and does not lower the
 * sequence. The role stays seated. A seated mirror that is still live
 * can Report the last sequence after ingress is stopped.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT. monetary_store() stays false.
 * qualified(), release_qualified(), hardware_qualified(), launched(),
 * gpu(), and broadcast() stay false. bytes_moved() stays 0.
 * This class opens no socket and starts no process.
 */
class RealmRoles {
public:
    bool Seat(const std::string& role, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Advance(int64_t sequence, std::string& err);
    bool Stop(const std::string& role, std::string& err);
    bool Report(const std::string& role, int64_t& sequence, std::string& err) const;
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool seated(const std::string& role) const;
    bool live(const std::string& role) const;
    int64_t sequence() const;

    bool monetary_store() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::vector<std::string> m_seated;
    std::vector<std::string> m_live;
    bool m_has_sequence{false};
    int64_t m_sequence{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_REALM_ROLES_REALM_ROLES_H
