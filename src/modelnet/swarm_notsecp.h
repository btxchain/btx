// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSECP_H
#define BTX_MODELNET_SWARM_NOTSECP_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. want_penalty asks this note for a
 * penalty.
 *
 * There is no secp256k1 Lightning penalty. secp_penalty and broadcast
 * stay false on every path.
 */
struct SwarmNotSecp {
    std::string channel_id;
    bool want_penalty{false};
};

/**
 * Outcome of noting a penalty request. secp_penalty and broadcast stay
 * false on every path. There is no secp256k1 Lightning penalty.
 */
struct SwarmNotSecpResult {
    std::string code;
    bool secp_penalty{false};
    bool broadcast{false};
};

/**
 * Note a penalty request without applying a secp256k1 Lightning penalty
 * or broadcasting. Order, first match wins: an empty channel_id is
 * CHANNEL. want_penalty is NO_PENALTY. Otherwise the note is NOTED and
 * err is clear. secp_penalty and broadcast stay false on every path.
 * There is no secp256k1 Lightning penalty.
 */
SwarmNotSecpResult SwarmNoteNotSecp(const SwarmNotSecp& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSECP_H
