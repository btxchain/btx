// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFAIL_H
#define BTX_MODELNET_SWARM_NOTNOFAIL_H

#include <string>

namespace modelnet {

/**
 * A local note that a failover might connect a peer.
 * want_connect asks this note to open one.
 *
 * A failover note opens no connection and moves no bytes. connected and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoFail {
    std::string peer_id;
    bool want_connect{false};
};

/**
 * Outcome of noting that no connection is opened. connected and bytes_moved
 * stay false on every path: a failover note opens no connection and moves
 * no bytes.
 */
struct SwarmNotNoFailResult {
    std::string code;
    bool connected{false};
    bool bytes_moved{false};
};

/**
 * Note that a failover opens no connection and moves no bytes.
 * Order, first match wins: an empty peer_id is PEER. want_connect is
 * NOT_CONNECTED. Otherwise the note is NOTED and err is cleared.
 * connected and bytes_moved stay false on every path. A failover note
 * opens no connection.
 */
SwarmNotNoFailResult SwarmNoteNotNoFail(const SwarmNotNoFail& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFAIL_H
