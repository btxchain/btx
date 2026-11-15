// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCLAIM32_H
#define BTX_MODELNET_SWARM_NOTNOCLAIM32_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one claim. bad_length records a preimage length
 * other than 32. want_claim asks this note to claim it.
 *
 * A preimage length other than 32 claims nothing. claimed stays false
 * and atoms stays 0 on every path.
 */
struct SwarmNotNoClaim32 {
    std::string claim_id;
    bool bad_length{false};
    bool want_claim{false};
};

/**
 * Outcome of noting a claim. claimed stays false and atoms stays 0
 * on every path. A preimage length other than 32 claims nothing.
 */
struct SwarmNotNoClaim32Result {
    std::string code;
    bool claimed{false};
    int64_t atoms{0};
};

/**
 * Note a claim without claiming it. Order, first match wins: an
 * empty claim_id is CLAIM. bad_length true is NOT_CLAIMED even when
 * want_claim is false. want_claim is HELD. Otherwise the note is
 * NOTED and err is cleared. claimed stays false and atoms stays 0 on
 * every path. A preimage length other than 32 claims nothing.
 */
SwarmNotNoClaim32Result SwarmNoteNotNoClaim32(const SwarmNotNoClaim32& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCLAIM32_H
