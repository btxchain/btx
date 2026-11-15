// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSPLIT_H
#define BTX_MODELNET_SWARM_NOTNOSPLIT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one disagreement. want_settle asks this note to settle
 * that disagreement.
 *
 * A disagreement is not a settlement. settled stays false and atoms stays 0
 * on every path.
 */
struct SwarmNotNoSplit {
    std::string report_id;
    bool disagree{false};
    bool want_settle{false};
};

/**
 * Outcome of noting a disagreement. settled stays false and atoms stays 0
 * on every path. A disagreement is not a settlement.
 */
struct SwarmNotNoSplitResult {
    std::string code;
    bool settled{false};
    int64_t atoms{0};
};

/**
 * Note a disagreement without settling it or moving atoms.
 * Order, first match wins: an empty report_id is REPORT.
 * disagree is SPLIT, even when want_settle is false.
 * want_settle is HELD.
 * Otherwise the note is NOTED and err is clear.
 * settled stays false and atoms stays 0 on every path.
 * A disagreement is not a settlement.
 */
SwarmNotNoSplitResult SwarmNoteNotNoSplit(const SwarmNotNoSplit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSPLIT_H
