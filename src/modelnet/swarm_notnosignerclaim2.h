// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSIGNERCLAIM2_H
#define BTX_MODELNET_SWARM_NOTNOSIGNERCLAIM2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one signer. signer records whether this note is
 * the signer. want_claim asks this note to claim it.
 *
 * A non-signer claims nothing. claimed stays false and atoms stays 0
 * on every path.
 */
struct SwarmNotNoSignerClaim2 {
    std::string claim_id;
    bool signer{false};
    bool want_claim{false};
};

/**
 * Outcome of noting a signer. claimed stays false and atoms stays 0
 * on every path. A non-signer claims nothing.
 */
struct SwarmNotNoSignerClaim2Result {
    std::string code;
    bool claimed{false};
    int64_t atoms{0};
};

/**
 * Note a signer without claiming it. Order, first match wins: an
 * empty claim_id is CLAIM. signer false is NOT_SIGNER even when
 * want_claim is false. want_claim is HELD. Otherwise the note is
 * NOTED and err is cleared. claimed stays false and atoms stays 0 on
 * every path. A non-signer claims nothing.
 */
SwarmNotNoSignerClaim2Result SwarmNoteNotNoSignerClaim2(const SwarmNotNoSignerClaim2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSIGNERCLAIM2_H
