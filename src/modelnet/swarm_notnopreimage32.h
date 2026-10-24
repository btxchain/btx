// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPREIMAGE32_H
#define BTX_MODELNET_SWARM_NOTNOPREIMAGE32_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one preimage. length is the preimage length in
 * bytes. want_claim asks this note to claim it.
 *
 * A preimage length other than 32 claims nothing. claimed stays false
 * and atoms stays 0 on every path.
 */
struct SwarmNotNoPreimage32 {
    std::string claim_id;
    int64_t length{0};
    bool want_claim{false};
};

/**
 * Outcome of noting a preimage. claimed stays false and atoms stays 0
 * on every path. A preimage length other than 32 claims nothing.
 */
struct SwarmNotNoPreimage32Result {
    std::string code;
    bool claimed{false};
    int64_t atoms{0};
};

/**
 * Note a preimage without claiming it. Order, first match wins: an
 * empty claim_id is CLAIM. length that is not exactly 32 is
 * NOT_CLAIMED even when want_claim is false. want_claim is HELD.
 * Otherwise the note is NOTED and err is cleared. claimed stays false
 * and atoms stays 0 on every path. A preimage length other than 32
 * claims nothing.
 */
SwarmNotNoPreimage32Result SwarmNoteNotNoPreimage32(const SwarmNotNoPreimage32& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPREIMAGE32_H
