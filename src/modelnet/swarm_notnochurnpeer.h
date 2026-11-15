// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCHURNPEER_H
#define BTX_MODELNET_SWARM_NOTNOCHURNPEER_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. churned records that the peer has left.
 * want_send asks this note to send.
 *
 * A churned peer sends nothing and moves no bytes. sent and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoChurnPeer {
    std::string peer_id;
    bool churned{false};
    bool want_send{false};
};

/**
 * Outcome of noting that nothing is sent. sent and bytes_moved stay
 * false on every path: a churned peer sends nothing and moves no bytes.
 */
struct SwarmNotNoChurnPeerResult {
    std::string code;
    bool sent{false};
    bool bytes_moved{false};
};

/**
 * Note that a churned peer sends nothing and moves no bytes.
 * Order, first match wins: an empty peer_id is PEER. churned true is
 * NOT_CONNECTED, even when want_send is false. want_send is HELD.
 * Otherwise the note is NOTED and err is cleared. sent and bytes_moved
 * stay false on every path. A churned peer sends nothing and moves no
 * bytes.
 */
SwarmNotNoChurnPeerResult SwarmNoteNotNoChurnPeer(const SwarmNotNoChurnPeer& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCHURNPEER_H
