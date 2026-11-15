// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPAIRS_H
#define BTX_MODELNET_SWARM_NOTNOPAIRS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about frozen pairs. want_unfreeze asks this note to
 * unfreeze them.
 *
 * INTEGER_LINEAR and INTEGER_MODEL stay eight frozen pairs.
 * unfrozen stays false and applied stays 0 on every path.
 */
struct SwarmNotNoPairs {
    std::string model_id;
    int64_t pair_count{0};
    bool want_unfreeze{false};
};

/**
 * Outcome of noting frozen pairs. unfrozen stays false and applied stays
 * 0 on every path. INTEGER_LINEAR and INTEGER_MODEL stay eight frozen
 * pairs.
 */
struct SwarmNotNoPairsResult {
    std::string code;
    bool unfrozen{false};
    int64_t applied{0};
};

/**
 * Note frozen pairs without unfreezing them.
 * Order, first match wins: an empty model_id is MODEL. pair_count not
 * exactly 8 is FROZEN even when want_unfreeze is false. want_unfreeze is
 * FROZEN. Otherwise the note is NOTED and err is cleared. unfrozen stays
 * false and applied stays 0 on every path. INTEGER_LINEAR and
 * INTEGER_MODEL stay eight frozen pairs.
 */
SwarmNotNoPairsResult SwarmNoteNotNoPairs(const SwarmNotNoPairs& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPAIRS_H
