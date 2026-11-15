// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMHQ_H
#define BTX_MODELNET_SWARM_NOTMHQ_H

#include <string>

namespace modelnet {

/**
 * A local note about one route. hop_count is a caller-supplied hop count.
 * want_qualify asks this note to qualify a multi-hop route.
 *
 * MultiHopQualified stays false. This note does not settle or broadcast.
 * qualified and multihop stay false on every path.
 */
struct SwarmNotMhq {
    std::string route_id;
    int hop_count{0};
    bool want_qualify{false};
};

/**
 * Outcome of noting a multi-hop qualification request. qualified and multihop
 * stay false on every path. MultiHopQualified stays false. This note does not
 * settle or broadcast.
 */
struct SwarmNotMhqResult {
    std::string code;
    bool qualified{false};
    bool multihop{false};
};

/**
 * Note a multi-hop qualification request without settling or broadcasting.
 * Order, first match wins: an empty route_id is ROUTE.
 * hop_count greater than 1 is UNQUALIFIED, even when want_qualify is false.
 * want_qualify is UNQUALIFIED.
 * Otherwise the note is NOTED and err is clear.
 * qualified and multihop stay false on every path.
 * MultiHopQualified stays false. This note does not settle or broadcast.
 */
SwarmNotMhqResult SwarmNoteNotMhq(const SwarmNotMhq& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMHQ_H
