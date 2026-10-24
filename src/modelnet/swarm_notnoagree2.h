// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOAGREE2_H
#define BTX_MODELNET_SWARM_NOTNOAGREE2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one quorum. want_settle asks this note to settle
 * that quorum.
 *
 * Agreement is not settlement. settled stays false and atoms stays 0 on
 * every path.
 */
struct SwarmNotNoAgree2 {
    std::string quorum_id;
    bool agreed{false};
    bool want_settle{false};
};

/**
 * Outcome of noting a quorum. settled stays false and atoms stays 0
 * on every path. Agreement is not settlement.
 */
struct SwarmNotNoAgree2Result {
    std::string code;
    bool settled{false};
    int64_t atoms{0};
};

/**
 * Note a quorum without settling it or moving atoms.
 * Order, first match wins: an empty quorum_id is QUORUM.
 * agreed is NOT_SETTLED, even when want_settle is false.
 * want_settle is HELD.
 * Otherwise the note is NOTED and err is clear.
 * settled stays false and atoms stays 0 on every path.
 * Agreement is not settlement.
 */
SwarmNotNoAgree2Result SwarmNoteNotNoAgree2(const SwarmNotNoAgree2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOAGREE2_H
