// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_LEASE_H
#define BTX_MODELNET_SWARM_AGENTS_LEASE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One in-process lease.
 *
 * The epoch starts at 1 and Grant does not move it. Grant admits when
 * until >= now. until < now is EXPIRED and leaves the epoch, the lease
 * id, and the admitted expiry unchanged. An empty lease id is LEASE
 * and stores nothing. A commit epoch other than the current epoch is
 * stale.
 */
class SwarmAgentLeaseBook {
public:
    bool Grant(const std::string& lease, int64_t until, int64_t now, std::string& err);
    bool admitted() const;
    uint64_t epoch() const;
    const std::string& lease_id() const;
    int64_t until() const;
    /** False, with STALE_EPOCH, when epoch is not the current epoch. */
    bool Matches(uint64_t epoch, std::string& err) const;

private:
    bool m_admitted{false};
    uint64_t m_epoch{1};
    std::string m_lease;
    int64_t m_until{0};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_LEASE_H
