// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHASHLOCK_H
#define BTX_MODELNET_SWARM_NOTNOHASHLOCK_H

#include <string>

namespace modelnet {

/**
 * A local note about one route. hashlock_only records whether the route
 * is a hashlock alone. want_qualify asks this note to qualify it.
 *
 * A hashlock is not a qualified routed network. qualified and multihop
 * stay false on every path.
 */
struct SwarmNotNoHashlock {
    std::string route_id;
    bool hashlock_only{false};
    bool want_qualify{false};
};

/**
 * Outcome of noting a route. qualified and multihop stay false on every
 * path. A hashlock is not a qualified routed network.
 */
struct SwarmNotNoHashlockResult {
    std::string code;
    bool qualified{false};
    bool multihop{false};
};

/**
 * Note a route without qualifying it. Order, first match wins: an empty
 * route_id is ROUTE. hashlock_only true is UNQUALIFIED even when
 * want_qualify is false. want_qualify is UNQUALIFIED. Otherwise the note
 * is NOTED and err is cleared. qualified and multihop stay false on every
 * path. A hashlock is not a qualified routed network.
 */
SwarmNotNoHashlockResult SwarmNoteNotNoHashlock(const SwarmNotNoHashlock& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHASHLOCK_H
