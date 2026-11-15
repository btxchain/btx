// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTRUSTCKPT2_H
#define BTX_MODELNET_SWARM_NOTNOTRUSTCKPT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one claim. checkpoint_only says the claim is a
 * checkpoint and not a trust grant. want_trust asks this note to treat
 * the claim as trust.
 *
 * A checkpoint-only claim is not trust. trusted stays false on every path.
 */
struct SwarmNotNoTrustCkpt2 {
    std::string claim_id;
    bool checkpoint_only{false};
    bool want_trust{false};
};

/**
 * Outcome of noting a claim. trusted stays false on every path.
 */
struct SwarmNotNoTrustCkpt2Result {
    std::string code;
    bool trusted{false};
};

/**
 * Note a claim without treating it as trust.
 * Order, first match wins: an empty claim_id is CLAIM. A checkpoint_only
 * note is NOT_TRUST, even when want_trust is false. want_trust is HELD.
 * Otherwise the note is NOTED and err is clear. trusted stays false on
 * every path. A checkpoint-only claim is not trust.
 */
SwarmNotNoTrustCkpt2Result SwarmNoteNotNoTrustCkpt2(const SwarmNotNoTrustCkpt2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTRUSTCKPT2_H
