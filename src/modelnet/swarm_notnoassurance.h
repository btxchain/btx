// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOASSURANCE_H
#define BTX_MODELNET_SWARM_NOTNOASSURANCE_H

#include <string>

namespace modelnet {

/**
 * A local note about one route. want_proof asks this note to treat
 * cumulative assurance as proof of work.
 *
 * proved and qualified stay false on every path. Cumulative assurance
 * is not proof of work and does not qualify a route.
 */
struct SwarmNotNoAssurance {
    std::string route_id;
    bool want_proof{false};
};

/**
 * Outcome of noting a route. proved and qualified stay false on every
 * path. Cumulative assurance is not proof of work and does not qualify
 * a route.
 */
struct SwarmNotNoAssuranceResult {
    std::string code;
    bool proved{false};
    bool qualified{false};
};

/**
 * Note a route without proving work or qualifying it. Order, first
 * match wins: an empty route_id is ROUTE. want_proof is NOT_WORK_PROOF.
 * Otherwise the note is NOTED and err is cleared. proved and qualified
 * stay false on every path. Cumulative assurance is not proof of work
 * and does not qualify a route.
 */
SwarmNotNoAssuranceResult SwarmNoteNotNoAssurance(const SwarmNotNoAssurance& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOASSURANCE_H
