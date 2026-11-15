// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_DECIDE_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_DECIDE_H

#include <cstddef>
#include <string>

namespace modelnet {

class SwarmFlagshipLedger;

/**
 * What a Record call would do. Store is the only outcome that may write.
 * The other outcomes leave the ledger unchanged.
 */
enum class SwarmFlagshipRecordOutcome {
    Store,
    Stage,
    Evidence,
    Order,
    Replay,
    Conflict,
};

struct SwarmFlagshipDecision {
    SwarmFlagshipRecordOutcome outcome{SwarmFlagshipRecordOutcome::Stage};
    std::size_t index{0};
};

/**
 * Classify one record attempt. First match wins:
 * a name outside the thirteen stages is Stage,
 * empty evidence is Evidence,
 * any earlier stage with no evidence is Order,
 * the same stage and the same evidence is Replay,
 * the same stage and different evidence is Conflict,
 * otherwise Store.
 * This function does not write.
 */
SwarmFlagshipDecision SwarmFlagshipDecide(const SwarmFlagshipLedger& ledger,
                                          const std::string& stage,
                                          const std::string& evidence);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_DECIDE_H
