// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOAGREE3_H
#define BTX_MODELNET_SWARM_NOTNOAGREE3_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one agreement. want_settle asks this note to settle
 * that agreement.
 *
 * An agreement is not a settlement. settled stays false and atoms stays 0
 * on every path.
 */
struct SwarmNotNoAgree3 {
    std::string agreement_id;
    bool agreement{false};
    bool want_settle{false};
};

/**
 * Outcome of noting an agreement. settled stays false and atoms stays 0
 * on every path. An agreement is not a settlement.
 */
struct SwarmNotNoAgree3Result {
    std::string code;
    bool settled{false};
    int64_t atoms{0};
};

/**
 * Note an agreement without settling it or moving atoms.
 * Order, first match wins: an empty agreement_id is AGREEMENT.
 * agreement is NOT_SETTLED, even when want_settle is false.
 * want_settle is HELD.
 * Otherwise the note is NOTED and err is clear.
 * settled stays false and atoms stays 0 on every path.
 * An agreement is not a settlement.
 */
SwarmNotNoAgree3Result SwarmNoteNotNoAgree3(const SwarmNotNoAgree3& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOAGREE3_H
