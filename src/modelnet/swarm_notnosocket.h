// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSOCKET_H
#define BTX_MODELNET_SWARM_NOTNOSOCKET_H

#include <string>

namespace modelnet {

/**
 * A local note about one rendezvous. want_open asks this note to open.
 *
 * A public rendezvous opens no socket and moves no bytes, so opened
 * stays false and bytes_moved stays false on every path.
 */
struct SwarmNotNoSocket {
    std::string rendezvous_id;
    bool want_open{false};
};

/**
 * Outcome of noting a rendezvous. opened stays false and bytes_moved
 * stays false on every path. A public rendezvous opens no socket and
 * moves no bytes.
 */
struct SwarmNotNoSocketResult {
    std::string code;
    bool opened{false};
    bool bytes_moved{false};
};

/**
 * Note a rendezvous without opening a socket.
 * Order, first match wins: an empty rendezvous_id is RENDEZVOUS.
 * want_open is NO_SOCKET. Otherwise the note is NOTED and err is
 * cleared. opened stays false and bytes_moved stays false on every
 * path. A public rendezvous opens no socket and moves no bytes.
 */
SwarmNotNoSocketResult SwarmNoteNotNoSocket(const SwarmNotNoSocket& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSOCKET_H
