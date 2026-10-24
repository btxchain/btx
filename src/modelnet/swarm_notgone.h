// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTGONE_H
#define BTX_MODELNET_SWARM_NOTGONE_H

#include <string>

namespace modelnet {

/**
 * A local note about one coordinator. want_vanish asks this note to inject
 * a coordinator disappearing with pending work.
 *
 * A coordinator disappearing with pending work has not been injected.
 * vanished stays false on every path.
 */
struct SwarmNotGone {
    std::string coord_id;
    bool want_vanish{false};
};

/**
 * Outcome of noting a disappearance request. vanished stays false on every
 * path: a coordinator disappearing with pending work has not been injected.
 */
struct SwarmNotGoneResult {
    std::string code;
    bool vanished{false};
};

/**
 * Note a disappearance request without injecting a coordinator disappearing
 * with pending work. Order, first match wins: an empty coord_id is COORD.
 * want_vanish is NOT_INJECTED. Otherwise the note is NOTED and err is clear.
 * vanished stays false on every path.
 */
SwarmNotGoneResult SwarmNoteNotGone(const SwarmNotGone& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTGONE_H
