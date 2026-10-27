// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORV2_H
#define BTX_MODELNET_SWARM_NOTNORV2_H

#include <string>

namespace modelnet {

/**
 * A local note about one rendezvous. rendezvous_id names the rendezvous.
 * public_rv marks a public rendezvous. want_open asks this note to open.
 *
 * A public rendezvous opens no socket. opened and bytes_moved stay false
 * on every path.
 */
struct SwarmNotNoRv2 {
    std::string rendezvous_id;
    bool public_rv{false};
    bool want_open{false};
};

/**
 * Outcome of noting a rendezvous. opened and bytes_moved stay false
 * on every path. A public rendezvous opens no socket.
 */
struct SwarmNotNoRv2Result {
    std::string code;
    bool opened{false};
    bool bytes_moved{false};
};

/**
 * Note a rendezvous without opening a socket.
 * Order, first match wins: an empty rendezvous_id is RV.
 * public_rv is NOT_OPENED even when want_open is false.
 * want_open is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * opened and bytes_moved stay false on every path.
 * A public rendezvous opens no socket.
 */
SwarmNotNoRv2Result SwarmNoteNotNoRv2(const SwarmNotNoRv2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORV2_H
