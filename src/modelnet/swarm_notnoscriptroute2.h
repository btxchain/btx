// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSCRIPTROUTE2_H
#define BTX_MODELNET_SWARM_NOTNOSCRIPTROUTE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one route. hashlock marks a hashlock on the route.
 * want_qualify asks this note to treat the route as script-qualified.
 *
 * A hashlock is not a script-qualified route.
 * MultiHopQualified stays false. qualified stays false on every path.
 */
struct SwarmNotNoScriptRoute2 {
    std::string route_id;
    bool hashlock{false};
    bool want_qualify{false};
};

/**
 * Outcome of noting a hashlock route. qualified stays false on every path.
 * MultiHopQualified stays false. A hashlock is not a script-qualified route.
 */
struct SwarmNotNoScriptRoute2Result {
    std::string code;
    bool qualified{false};
};

/**
 * Note a hashlock route without script-qualifying it.
 * Order, first match wins: an empty route_id is ROUTE.
 * hashlock is NOT_QUALIFIED, even when want_qualify is false.
 * want_qualify is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * qualified stays false on every path. MultiHopQualified stays false.
 * A hashlock is not a script-qualified route.
 */
SwarmNotNoScriptRoute2Result SwarmNoteNotNoScriptRoute2(const SwarmNotNoScriptRoute2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSCRIPTROUTE2_H
