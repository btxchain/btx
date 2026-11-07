// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNIXL_H
#define BTX_MODELNET_SWARM_NOTNIXL_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. want_transfer asks this note to move bytes
 * through NIXL.
 *
 * NIXL is not installed, so this note does not transfer.
 * bytes_moved stays false on every path.
 */
struct SwarmNotNixl {
    std::string page_id;
    bool nixl_present{false};
    bool want_transfer{false};
};

/**
 * Outcome of noting a NIXL transfer request. bytes_moved stays false on
 * every path: NIXL is not installed, so this note does not transfer.
 */
struct SwarmNotNixlResult {
    std::string code;
    bool bytes_moved{false};
};

/**
 * Note a NIXL transfer request without moving bytes.
 * Order, first match wins: an empty page_id is NIXL.
 * !nixl_present is ENGINE_ABSENT, even when want_transfer is true.
 * want_transfer is HELD and err is clear.
 * Otherwise the note is NOTED and err is clear.
 * bytes_moved stays false on every path.
 */
SwarmNotNixlResult SwarmNoteNotNixl(const SwarmNotNixl& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNIXL_H
