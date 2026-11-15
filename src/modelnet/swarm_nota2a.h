// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTA2A_H
#define BTX_MODELNET_SWARM_NOTA2A_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. want_connect asks this note to open
 * an agent-to-agent session with that peer.
 *
 * This note does not open an agent-to-agent session. connected and
 * launched stay false on every path.
 */
struct SwarmNotA2a {
    std::string peer_id;
    bool want_connect{false};
};

/**
 * Outcome of noting a connect request. connected and launched stay
 * false on every path: this note does not open an agent-to-agent session.
 */
struct SwarmNotA2aResult {
    std::string code;
    bool connected{false};
    bool launched{false};
};

/**
 * Note a connect request without opening an agent-to-agent session.
 * Order, first match wins: an empty peer_id is PEER. want_connect is
 * NOT_CONNECTED. Otherwise the note is NOTED and err is clear.
 * connected and launched stay false on every path. This note does not
 * open an agent-to-agent session.
 */
SwarmNotA2aResult SwarmNoteNotA2a(const SwarmNotA2a& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTA2A_H
