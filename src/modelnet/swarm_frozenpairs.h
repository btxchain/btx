// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FROZENPAIRS_H
#define BTX_MODELNET_SWARM_FROZENPAIRS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of frozen pairs for one model. model_id names the note.
 * pair_count is the count the note was asked to record. want_unfreeze
 * asks this note to unfreeze the pairs.
 *
 * INTEGER_LINEAR and INTEGER_MODEL stay eight frozen pairs. changed
 * stays false on every path. This note does not edit a model.
 */
struct SwarmFrozenPairs {
    std::string model_id;
    int64_t pair_count{0};
    bool want_unfreeze{false};
};

/**
 * Outcome of noting frozen pairs. changed stays false: eight pairs are
 * noted and not changed. INTEGER_LINEAR and INTEGER_MODEL stay eight
 * frozen pairs. This note does not edit a model.
 */
struct SwarmFrozenPairsResult {
    std::string code;
    bool changed{false};
};

/**
 * Note frozen pairs without editing a model.
 * Order, first match wins: an empty model_id or pair_count below 0 is
 * PAIRS. changed stays false and err is PAIRS. want_unfreeze is FROZEN,
 * even when pair_count is 8. changed stays false and err is FROZEN.
 * pair_count other than 8 is FROZEN. changed stays false and err is
 * FROZEN. Otherwise the eight pairs are NOTED. changed stays false and
 * err is cleared.
 * changed stays false on every path. INTEGER_LINEAR and INTEGER_MODEL
 * stay eight frozen pairs. This note does not edit a model.
 */
SwarmFrozenPairsResult SwarmNoteFrozenPairs(const SwarmFrozenPairs& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FROZENPAIRS_H
