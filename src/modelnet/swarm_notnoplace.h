// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPLACE_H
#define BTX_MODELNET_SWARM_NOTNOPLACE_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. want_place asks this note to place the page.
 *
 * A placement note moves no bytes. placed and bytes_moved stay false on
 * every path.
 */
struct SwarmNotNoPlace {
    std::string page_id;
    bool want_place{false};
};

/**
 * Outcome of noting a placement. placed and bytes_moved stay false on
 * every path. A placement note moves no bytes.
 */
struct SwarmNotNoPlaceResult {
    std::string code;
    bool placed{false};
    bool bytes_moved{false};
};

/**
 * Note a page without placing it.
 * Order, first match wins: an empty page_id is PAGE.
 * want_place is NOT_PLACED.
 * Otherwise the note is NOTED and err is clear.
 * placed and bytes_moved stay false on every path. A placement note
 * moves no bytes.
 */
SwarmNotNoPlaceResult SwarmNoteNotNoPlace(const SwarmNotNoPlace& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPLACE_H
