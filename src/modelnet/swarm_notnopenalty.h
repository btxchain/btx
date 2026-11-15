// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPENALTY_H
#define BTX_MODELNET_SWARM_NOTNOPENALTY_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_penalty asks this note for a
 * penalty.
 *
 * There is no secp256k1 Lightning penalty. secp_penalty and applied
 * stay false on every path.
 */
struct SwarmNotNoPenalty {
    std::string channel_id;
    bool want_penalty{false};
};

/**
 * Outcome of noting a penalty request. secp_penalty and applied stay
 * false on every path. There is no secp256k1 Lightning penalty.
 */
struct SwarmNotNoPenaltyResult {
    std::string code;
    bool secp_penalty{false};
    bool applied{false};
};

/**
 * Note a penalty request without applying a secp256k1 Lightning penalty.
 * Order, first match wins: an empty channel_id is CHANNEL. want_penalty
 * is REFUSED. Otherwise the note is NOTED and err is clear. secp_penalty
 * and applied stay false on every path. There is no secp256k1 Lightning
 * penalty.
 */
SwarmNotNoPenaltyResult SwarmNoteNotNoPenalty(const SwarmNotNoPenalty& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPENALTY_H
