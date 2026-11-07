// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPRE32B_H
#define BTX_MODELNET_SWARM_NOTNOPRE32B_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one claim. length is the preimage length in
 * bytes. want_claim asks this note to claim it.
 *
 * A preimage length other than 32 claims nothing. claimed stays false
 * and atoms stays 0 on every path.
 */
struct SwarmNotNoPre32b {
    std::string claim_id;
    int length{0};
    bool want_claim{false};
};

/**
 * Outcome of noting a claim. claimed stays false and atoms stays 0
 * on every path. A preimage length other than 32 claims nothing.
 */
struct SwarmNotNoPre32bResult {
    std::string code;
    bool claimed{false};
    int64_t atoms{0};
};

/**
 * Note a claim without claiming it. Order, first match wins: an
 * empty claim_id is CLAIM. length that is not exactly 32 is
 * NOT_CLAIMED even when want_claim is false. want_claim is HELD.
 * Otherwise the note is NOTED and err is cleared. claimed stays false
 * and atoms stays 0 on every path. A preimage length other than 32
 * claims nothing.
 */
SwarmNotNoPre32bResult SwarmNoteNotNoPre32b(const SwarmNotNoPre32b& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPRE32B_H
