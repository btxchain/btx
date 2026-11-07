// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTADOPT_H
#define BTX_MODELNET_SWARM_NOTADOPT_H

#include <string>

namespace modelnet {

/**
 * A local note about one qualified descendant. want_adopt asks this note to
 * adopt that descendant on a second node.
 *
 * Follow-staging has not adopted a qualified descendant on a second node.
 * adopted stays false on every path.
 */
struct SwarmNotAdopt {
    std::string descendant_id;
    bool want_adopt{false};
};

/**
 * Outcome of noting an adopt request. adopted stays false on every path:
 * follow-staging has not adopted a qualified descendant on a second node.
 */
struct SwarmNotAdoptResult {
    std::string code;
    bool adopted{false};
};

/**
 * Note an adopt request without adopting the qualified descendant.
 * Order, first match wins: an empty descendant_id is DESCENDANT. want_adopt
 * is NOT_ADOPTED. Otherwise the note is NOTED and err is clear.
 * adopted stays false on every path.
 */
SwarmNotAdoptResult SwarmNoteNotAdopt(const SwarmNotAdopt& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTADOPT_H
