// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSOCKET_H
#define BTX_MODELNET_SWARM_NOTSOCKET_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. want_connect asks this note to open a socket.
 *
 * Family discovery stays a local catalog and opens no socket.
 * connected and socket_opened stay false on every path.
 */
struct SwarmNotSocket {
    std::string peer_id;
    bool want_connect{false};
};

/**
 * Outcome of noting a socket request. connected and socket_opened stay false
 * on every path: family discovery stays a local catalog and opens no socket.
 */
struct SwarmNotSocketResult {
    std::string code;
    bool connected{false};
    bool socket_opened{false};
};

/**
 * Note a peer without opening a socket.
 * Order, first match wins: an empty peer_id is PEER.
 * want_connect is NO_SOCKET.
 * Otherwise the note is NOTED and err is clear.
 * connected and socket_opened stay false on every path. Family discovery
 * stays a local catalog and opens no socket.
 */
SwarmNotSocketResult SwarmNoteNotSocket(const SwarmNotSocket& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSOCKET_H
