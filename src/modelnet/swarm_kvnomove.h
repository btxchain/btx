// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVNOMOVE_H
#define BTX_MODELNET_SWARM_KVNOMOVE_H

#include <string>

namespace modelnet {

/**
 * A local note about one KV page. want_transfer asks this note to move
 * page bytes. engine_present is a flag, not a transfer.
 *
 * This note does not move KV bytes. bytes_moved stays false on every path.
 */
struct SwarmKvNoMove {
    std::string page_id;
    bool engine_present{false};
    bool want_transfer{false};
};

/**
 * Outcome of noting a page. bytes_moved stays false on every path.
 */
struct SwarmKvNoMoveResult {
    std::string code;
    bool bytes_moved{false};
};

/**
 * Note a page without moving KV bytes.
 * Order, first match wins: an empty page_id is KV.
 * A missing engine is ENGINE_ABSENT, even when want_transfer is true.
 * want_transfer with a present engine is HELD and err is cleared.
 * Otherwise the note is NOTED and err is clear.
 * bytes_moved stays false on every path. An engine flag is not a KV transfer.
 */
SwarmKvNoMoveResult SwarmNoteKvNoMove(const SwarmKvNoMove& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVNOMOVE_H
