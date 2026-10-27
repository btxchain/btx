// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCHURN_H
#define BTX_MODELNET_SWARM_NOTCHURN_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. want_recover asks this note to observe
 * peer-churn recovery.
 *
 * This note does not observe peer-churn recovery across hosts.
 * recovered and restarted stay false on every path.
 */
struct SwarmNotChurn {
    std::string peer_id;
    bool want_recover{false};
};

/**
 * Outcome of noting a peer-churn request. recovered and restarted stay
 * false on every path: this note does not observe peer-churn recovery
 * across hosts.
 */
struct SwarmNotChurnResult {
    std::string code;
    bool recovered{false};
    bool restarted{false};
};

/**
 * Note a peer without observing peer-churn recovery. Order, first match
 * wins: an empty peer_id is PEER. want_recover is NOT_OBSERVED. Otherwise
 * the note is NOTED and err is clear. recovered and restarted stay false
 * on every path. This note does not observe peer-churn recovery across
 * hosts.
 */
SwarmNotChurnResult SwarmNoteNotChurn(const SwarmNotChurn& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCHURN_H
