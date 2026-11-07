// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTLEASE_H
#define BTX_MODELNET_SWARM_NOTLEASE_H

#include <string>

namespace modelnet {

/**
 * A local note about one lease. want_replace asks this note to start a
 * replacement coordinator during lease expiry.
 *
 * A replacement coordinator starting during lease expiry has not been
 * injected. replaced stays false on every path.
 */
struct SwarmNotLease {
    std::string lease_id;
    bool want_replace{false};
};

/**
 * Outcome of noting a lease. replaced stays false on every path: a
 * replacement coordinator starting during lease expiry has not been
 * injected.
 */
struct SwarmNotLeaseResult {
    std::string code;
    bool replaced{false};
};

/**
 * Note a lease without injecting a replacement coordinator.
 * Order, first match wins: an empty lease_id is LEASE.
 * want_replace is NOT_INJECTED.
 * Otherwise the note is NOTED and err is clear.
 * replaced stays false on every path. A replacement coordinator starting
 * during lease expiry has not been injected.
 */
SwarmNotLeaseResult SwarmNoteNotLease(const SwarmNotLease& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTLEASE_H
