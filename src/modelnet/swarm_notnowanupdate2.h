// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWANUPDATE2_H
#define BTX_MODELNET_SWARM_NOTNOWANUPDATE2_H

#include <string>

namespace modelnet {

/**
 * A local island note. want_exchange asks this note to exchange a WAN update.
 *
 * An island note exchanges no WAN update and moves no bytes.
 * exchanged stays false on every path. bytes_moved stays false on every path.
 */
struct SwarmNotNoWanUpdate2 {
    std::string island_id;
    bool want_exchange{false};
};

/**
 * Outcome of noting an island WAN-update request. exchanged stays false and
 * bytes_moved stays false on every path: an island note exchanges no WAN
 * update and moves no bytes.
 */
struct SwarmNotNoWanUpdate2Result {
    std::string code;
    bool exchanged{false};
    bool bytes_moved{false};
};

/**
 * Note an island request without exchanging a WAN update or moving bytes.
 * Order, first match wins: an empty island_id is ISLAND.
 * want_exchange is HELD.
 * Otherwise the note is NOTED and err is clear.
 * exchanged stays false and bytes_moved stays false on every path.
 */
SwarmNotNoWanUpdate2Result SwarmNoteNotNoWanUpdate2(const SwarmNotNoWanUpdate2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWANUPDATE2_H
