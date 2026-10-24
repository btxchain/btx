// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMULTIHOP2_H
#define BTX_MODELNET_SWARM_NOTNOMULTIHOP2_H

#include <string>

namespace modelnet {

/**
 * A local note about one route. want_qualify asks this note to qualify
 * a script-enforceable multi-hop route.
 *
 * A unit note does not qualify a script-enforceable multi-hop route.
 * qualified and multihop stay false on every path.
 */
struct SwarmNotNoMultihop2 {
    std::string route_id;
    bool want_qualify{false};
};

/**
 * Outcome of noting a multi-hop qualification request. qualified and multihop
 * stay false on every path. A unit note does not qualify a script-enforceable
 * multi-hop route.
 */
struct SwarmNotNoMultihop2Result {
    std::string code;
    bool qualified{false};
    bool multihop{false};
};

/**
 * Note a multi-hop qualification request without qualifying the route.
 * Order, first match wins: an empty route_id is ROUTE.
 * want_qualify is UNQUALIFIED.
 * Otherwise the note is NOTED and err is clear.
 * qualified and multihop stay false on every path.
 * A unit note does not qualify a script-enforceable multi-hop route.
 */
SwarmNotNoMultihop2Result SwarmNoteNotNoMultihop2(const SwarmNotNoMultihop2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMULTIHOP2_H
