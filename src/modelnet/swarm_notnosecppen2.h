// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSECPPEN2_H
#define BTX_MODELNET_SWARM_NOTNOSECPPEN2_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. secp_penalty asks this note to apply
 * a penalty. want_penalty asks this note for a penalty.
 *
 * There is no secp256k1 Lightning penalty. penalized stays false on
 * every path.
 */
struct SwarmNotNoSecpPen2 {
    std::string channel_id;
    bool secp_penalty{false};
    bool want_penalty{false};
};

/**
 * Outcome of noting a penalty request. penalized stays false on every
 * path. There is no secp256k1 Lightning penalty.
 */
struct SwarmNotNoSecpPen2Result {
    std::string code;
    bool penalized{false};
};

/**
 * Note a penalty request without applying a secp256k1 Lightning penalty.
 * Order, first match wins: an empty channel_id is CHANNEL. secp_penalty
 * is NOT_PENALIZED even when want_penalty is false. want_penalty is
 * HELD. Otherwise the note is NOTED and err is cleared. penalized stays
 * false on every path. There is no secp256k1 Lightning penalty.
 */
SwarmNotNoSecpPen2Result SwarmNoteNotNoSecpPen2(const SwarmNotNoSecpPen2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSECPPEN2_H
