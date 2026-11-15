// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMOONCAKE_H
#define BTX_MODELNET_SWARM_NOTMOONCAKE_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. mooncake_present records whether Mooncake is
 * installed. want_transfer asks this note to move bytes.
 *
 * Mooncake is not installed, so this note does not transfer.
 * bytes_moved stays false on every path.
 */
struct SwarmNotMooncake {
    std::string page_id;
    bool mooncake_present{false};
    bool want_transfer{false};
};

/**
 * Outcome of noting a Mooncake request. bytes_moved stays false on every
 * path: Mooncake is not installed, so this note does not transfer.
 */
struct SwarmNotMooncakeResult {
    std::string code;
    bool bytes_moved{false};
};

/**
 * Note a Mooncake request without moving bytes.
 * Order, first match wins: an empty page_id is MOONCAKE.
 * Absent Mooncake is ENGINE_ABSENT, even when want_transfer is true.
 * want_transfer with Mooncake present is HELD and err is clear.
 * Otherwise the note is NOTED and err is clear.
 * bytes_moved stays false on every path.
 */
SwarmNotMooncakeResult SwarmNoteNotMooncake(const SwarmNotMooncake& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMOONCAKE_H
