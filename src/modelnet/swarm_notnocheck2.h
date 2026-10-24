// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCHECK2_H
#define BTX_MODELNET_SWARM_NOTNOCHECK2_H

#include <string>

namespace modelnet {

/**
 * A local note about one claim. checkpoint_only says the claim is a
 * checkpoint and not a trust grant. want_trust asks this note to treat
 * the claim as trust.
 *
 * A checkpoint-only claim is not trust. trusted and admitted stay false
 * on every path.
 */
struct SwarmNotNoCheck2 {
    std::string claim_id;
    bool checkpoint_only{false};
    bool want_trust{false};
};

/**
 * Outcome of noting a claim. trusted and admitted stay false on every
 * path.
 */
struct SwarmNotNoCheck2Result {
    std::string code;
    bool trusted{false};
    bool admitted{false};
};

/**
 * Note a claim without treating it as trust or admitting it.
 * Order, first match wins: an empty claim_id is CLAIM. A checkpoint_only
 * note is NOT_TRUST, even when want_trust is false. want_trust is HELD.
 * Otherwise the note is NOTED and err is cleared. trusted and admitted
 * stay false on every path. A checkpoint-only claim is not trust.
 */
SwarmNotNoCheck2Result SwarmNoteNotNoCheck2(const SwarmNotNoCheck2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCHECK2_H
