// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLEASE_H
#define BTX_MODELNET_SWARM_NOTNOLEASE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one lease. expired records that the lease ended.
 * want_spend asks this note to spend.
 *
 * Lease expiry does not spend. spent stays false and atoms stays 0 on
 * every path.
 */
struct SwarmNotNoLease {
    std::string lease_id;
    bool expired{false};
    bool want_spend{false};
};

/**
 * Outcome of noting a lease. spent stays false and atoms stays 0 on
 * every path. Lease expiry does not spend.
 */
struct SwarmNotNoLeaseResult {
    std::string code;
    bool spent{false};
    int64_t atoms{0};
};

/**
 * Note a lease without spending. Order, first match wins: an empty
 * lease_id is LEASE. expired is HELD even when want_spend is false.
 * want_spend is HELD. Otherwise the note is NOTED and err is clear.
 * spent stays false and atoms stays 0 on every path. Lease expiry does
 * not spend.
 */
SwarmNotNoLeaseResult SwarmNoteNotNoLease(const SwarmNotNoLease& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLEASE_H
