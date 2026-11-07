// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CKPTONLY_H
#define BTX_MODELNET_SWARM_CKPTONLY_H

#include <string>

namespace modelnet {

/**
 * A checkpoint-only claim is not trust. claim_id names the claim.
 * checkpoint_only marks a checkpoint record. want_trust asks this note
 * to grant trust.
 *
 * A checkpoint-only claim is not trust. A trust request is held.
 * trusted stays false on every path.
 */
struct SwarmCkptOnly {
    std::string claim_id;
    bool checkpoint_only{false};
    bool want_trust{false};
};

/**
 * Outcome of noting a checkpoint-only claim. trusted stays false on every
 * path.
 */
struct SwarmCkptOnlyResult {
    std::string code;
    bool trusted{false};
};

/**
 * Note a checkpoint-only claim. It is not trust.
 * Order, first match wins: an empty claim_id is CLAIM.
 * checkpoint_only true is NOT_TRUST, even when want_trust is false.
 * want_trust true is HELD.
 * Otherwise the code is NOTED and err is cleared.
 * trusted stays false on every path.
 * A checkpoint-only claim is not trust.
 */
SwarmCkptOnlyResult SwarmNoteCkptOnly(const SwarmCkptOnly& claim, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CKPTONLY_H
