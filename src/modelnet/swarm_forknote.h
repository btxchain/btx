// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FORKNOTE_H
#define BTX_MODELNET_SWARM_FORKNOTE_H

#include <string>

namespace modelnet {

/**
 * A note that two fork sides were compared. Noting a fork does not average
 * weights and does not write a merged digest.
 */
struct SwarmForkNote {
    std::string left_id;
    std::string right_id;
    std::string left_digest;
    std::string right_digest;
    bool want_average{false};
};

/**
 * Outcome of noting a fork. averaged is always false: divergent digests
 * are recorded, never averaged.
 */
struct SwarmForkNoteResult {
    bool averaged{false};
    std::string code;
};

/**
 * Note a fork without averaging weights.
 * Empty identifiers or digests yield FORK.
 * A request to average yields AVERAGE_REFUSED, including when the digests match.
 * Unequal digests yield DIVERGED. Matching digests yield NOTED.
 */
SwarmForkNoteResult SwarmNoteFork(const SwarmForkNote& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FORKNOTE_H
