// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_JOINFLAG_H
#define BTX_MODELNET_SWARM_JOINFLAG_H

#include <string>

namespace modelnet {

/**
 * A local note about joining a model. model_id names the model.
 * modelnet_on records whether modelnet is on. extra_flag_required asks
 * this note for an extra startup flag before join-on-acquire.
 *
 * Join-on-acquire does not need an extra startup flag. This note does
 * not open a socket and does not join a network. joined and
 * socket_opened stay false on every path. No hostnames or IPs are used.
 */
struct SwarmJoinFlag {
    std::string model_id;
    bool modelnet_on{false};
    bool extra_flag_required{false};
};

/**
 * Outcome of noting a join flag. joined and socket_opened stay false on
 * every path: this note does not open a socket and does not join a
 * network.
 */
struct SwarmJoinFlagResult {
    bool joined{false};
    bool socket_opened{false};
    std::string code;
};

/**
 * Note a join flag without opening a socket or joining a network.
 * Order, first match wins: an empty model_id is JOIN. extra_flag_required
 * is NO_FLAG, including when modelnet_on is true. !modelnet_on is
 * MODELNET. Otherwise the note is NOTED and err is cleared.
 * joined and socket_opened stay false on every path. Join-on-acquire
 * does not need an extra startup flag. This note does not open a socket
 * and does not join a network.
 */
SwarmJoinFlagResult SwarmNoteJoinFlag(const SwarmJoinFlag& flag, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_JOINFLAG_H
