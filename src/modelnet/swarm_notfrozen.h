// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFROZEN_H
#define BTX_MODELNET_SWARM_NOTFROZEN_H

#include <string>

namespace modelnet {

/**
 * A local note about frozen pairs. pair_id names the pair set.
 * pair_count is the number of pairs. want_unfreeze asks this note to
 * unfreeze them.
 *
 * INTEGER_LINEAR and INTEGER_MODEL stay eight frozen pairs.
 * unfrozen stays false on every path. This note does not unfreeze pairs.
 */
struct SwarmNotFrozen {
    std::string pair_id;
    int pair_count{0};
    bool want_unfreeze{false};
};

/**
 * Outcome of noting frozen pairs. unfrozen stays false on every path.
 */
struct SwarmNotFrozenResult {
    std::string code;
    bool unfrozen{false};
};

/**
 * Note frozen pairs without unfreezing them.
 * Order, first match wins: an empty pair_id is PAIR. pair_count other
 * than 8, or want_unfreeze, is FROZEN. Otherwise the note is NOTED and
 * err is clear.
 * unfrozen stays false on every path. INTEGER_LINEAR and INTEGER_MODEL
 * stay eight frozen pairs. This note does not unfreeze pairs.
 */
SwarmNotFrozenResult SwarmNoteNotFrozen(const SwarmNotFrozen& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFROZEN_H
