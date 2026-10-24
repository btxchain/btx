// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHTLC2_H
#define BTX_MODELNET_SWARM_NOTNOHTLC2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one claim. p2mr_leaf records whether this claim
 * is a P2MR HTLC leaf. want_claim asks this note to claim it.
 *
 * A contributor claim that is not a P2MR HTLC leaf claims nothing.
 * claimed stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoHtlc2 {
    std::string claim_id;
    bool p2mr_leaf{false};
    bool want_claim{false};
};

/**
 * Outcome of noting a claim. claimed stays false and atoms stays 0
 * on every path. A contributor claim that is not a P2MR HTLC leaf
 * claims nothing.
 */
struct SwarmNotNoHtlc2Result {
    std::string code;
    bool claimed{false};
    int64_t atoms{0};
};

/**
 * Note a claim without claiming it. Order, first match wins: an
 * empty claim_id is CLAIM. p2mr_leaf false is NOT_CLAIMED even when
 * want_claim is false. want_claim is HELD. Otherwise the note is
 * NOTED and err is cleared. claimed stays false and atoms stays 0 on
 * every path. A contributor claim that is not a P2MR HTLC leaf claims
 * nothing.
 */
SwarmNotNoHtlc2Result SwarmNoteNotNoHtlc2(const SwarmNotNoHtlc2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHTLC2_H
