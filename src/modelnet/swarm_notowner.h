// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTOWNER_H
#define BTX_MODELNET_SWARM_NOTOWNER_H

#include <string>

namespace modelnet {

/**
 * A local note about one cache page. page_id names the page.
 * want_transfer asks this note to move bytes because a cache owner
 * disappeared during transfer.
 *
 * A cache owner disappearing during transfer has not been shown.
 * bytes_moved stays false on every path.
 */
struct SwarmNotOwner {
    std::string page_id;
    bool want_transfer{false};
};

/**
 * Outcome of noting a missing cache owner. bytes_moved stays false on
 * every path: a cache owner disappearing during transfer has not been
 * shown.
 */
struct SwarmNotOwnerResult {
    std::string code;
    bool bytes_moved{false};
};

/**
 * Note a missing cache owner without moving bytes.
 * Order, first match wins: an empty page_id is PAGE. want_transfer is
 * NOT_SHOWN. Otherwise the note is NOTED and err is clear.
 * bytes_moved stays false on every path. A cache owner disappearing
 * during transfer has not been shown.
 */
SwarmNotOwnerResult SwarmNoteNotOwner(const SwarmNotOwner& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTOWNER_H
