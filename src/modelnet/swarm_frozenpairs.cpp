// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_frozenpairs.h>

#include <cstdint>

namespace modelnet {

SwarmFrozenPairsResult SwarmNoteFrozenPairs(const SwarmFrozenPairs& note, std::string& err)
{
    SwarmFrozenPairsResult result;
    result.changed = false;
    if (note.model_id.empty() || note.pair_count < 0) {
        result.code = "PAIRS";
        result.changed = false;
        err = "PAIRS";
        return result;
    }
    // INTEGER_LINEAR and INTEGER_MODEL stay eight frozen pairs.
    // want_unfreeze does not unfreeze them, even when pair_count is 8.
    // This note does not edit a model.
    if (note.want_unfreeze) {
        result.code = "FROZEN";
        result.changed = false;
        err = "FROZEN";
        return result;
    }
    // A count other than eight stays frozen and is not changed.
    if (note.pair_count != 8) {
        result.code = "FROZEN";
        result.changed = false;
        err = "FROZEN";
        return result;
    }
    // Eight pairs are noted and not changed.
    result.code = "NOTED";
    result.changed = false;
    err.clear();
    return result;
}

} // namespace modelnet
