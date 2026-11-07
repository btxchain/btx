// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCLAIMKEY_H
#define BTX_MODELNET_SWARM_NOTNOCLAIMKEY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one claim key. signer records whether this key is
 * the signer. want_claim asks this note to claim it.
 *
 * A claim key that is not the signer claims nothing. claimed stays false
 * and atoms stays 0 on every path.
 */
struct SwarmNotNoClaimKey {
    std::string claim_id;
    bool signer{false};
    bool want_claim{false};
};

/**
 * Outcome of noting a claim key. claimed stays false and atoms stays 0
 * on every path. A claim key that is not the signer claims nothing.
 */
struct SwarmNotNoClaimKeyResult {
    std::string code;
    bool claimed{false};
    int64_t atoms{0};
};

/**
 * Note a claim key without claiming it. Order, first match wins: an
 * empty claim_id is CLAIM. signer false is NOT_SIGNER even when
 * want_claim is false. want_claim is REFUSED. Otherwise the note is
 * NOTED and err is cleared. claimed stays false and atoms stays 0 on
 * every path. A claim key that is not the signer claims nothing.
 */
SwarmNotNoClaimKeyResult SwarmNoteNotNoClaimKey(const SwarmNotNoClaimKey& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCLAIMKEY_H
