// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGUEST_H
#define BTX_MODELNET_SWARM_NOTNOGUEST_H

#include <string>

namespace modelnet {

/**
 * A local note about one host. want_agent asks this note to treat a
 * guest agent as present.
 *
 * This note does not mark a guest agent present and does not mark
 * Windows passed, so guest_agent and passed stay false on every path.
 */
struct SwarmNotNoGuest {
    std::string host_id;
    bool want_agent{false};
};

/**
 * Outcome of noting a host. guest_agent and passed stay false on every
 * path: this note does not mark a guest agent present and does not mark
 * Windows passed.
 */
struct SwarmNotNoGuestResult {
    std::string code;
    bool guest_agent{false};
    bool passed{false};
};

/**
 * Note a host without marking a guest agent present.
 * Order, first match wins: an empty host_id is HOST. want_agent is
 * UNQUALIFIED. Otherwise the note is NOTED and err is clear.
 * guest_agent and passed stay false on every path. This note does not
 * mark a guest agent present and does not mark Windows passed.
 */
SwarmNotNoGuestResult SwarmNoteNotNoGuest(const SwarmNotNoGuest& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGUEST_H
