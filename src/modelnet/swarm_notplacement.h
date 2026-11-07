// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPLACEMENT_H
#define BTX_MODELNET_SWARM_NOTPLACEMENT_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. want_place asks this note to place the page.
 *
 * This note does not place a page and does not move bytes. placed and
 * bytes_moved stay false on every path.
 */
struct SwarmNotPlacement {
    std::string page_id;
    bool want_place{false};
};

/**
 * Outcome of noting a placement request. placed and bytes_moved stay false
 * on every path.
 */
struct SwarmNotPlacementResult {
    std::string code;
    bool placed{false};
    bool bytes_moved{false};
};

/**
 * Note a page without placing it.
 * Order, first match wins: an empty page_id is PAGE and err is PAGE.
 * want_place is HELD and err is cleared. Otherwise the note is NOTED and
 * err is cleared. placed and bytes_moved stay false on every path.
 */
SwarmNotPlacementResult SwarmNoteNotPlacement(const SwarmNotPlacement& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPLACEMENT_H
