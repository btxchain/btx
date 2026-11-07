// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORENDEZVOUS2_H
#define BTX_MODELNET_SWARM_NOTNORENDEZVOUS2_H

#include <string>

namespace modelnet {

/**
 * A local note about one rendezvous. meet_id names the meet.
 * public_meet marks a public rendezvous. want_open asks this
 * note to open.
 *
 * A public rendezvous opens no socket. opened and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoRendezvous2 {
    std::string meet_id;
    bool public_meet{false};
    bool want_open{false};
};

/**
 * Outcome of noting a rendezvous. opened and bytes_moved stay false
 * on every path. A public rendezvous opens no socket.
 */
struct SwarmNotNoRendezvous2Result {
    std::string code;
    bool opened{false};
    bool bytes_moved{false};
};

/**
 * Note a rendezvous without opening a socket.
 * Order, first match wins: an empty meet_id is MEET.
 * public_meet is NOT_OPEN even when want_open is false.
 * want_open is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * opened and bytes_moved stay false on every path.
 * A public rendezvous opens no socket.
 */
SwarmNotNoRendezvous2Result SwarmNoteNotNoRendezvous2(const SwarmNotNoRendezvous2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORENDEZVOUS2_H
