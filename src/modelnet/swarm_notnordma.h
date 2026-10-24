// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORDMA_H
#define BTX_MODELNET_SWARM_NOTNORDMA_H

#include <string>

namespace modelnet {

/**
 * A local note about one link. want_move asks this note to move bytes.
 *
 * Missing RDMA moves no bytes. moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoRdma {
    std::string link_id;
    bool want_move{false};
};

/**
 * Outcome of noting a move request. moved and bytes_moved stay false on
 * every path: missing RDMA moves no bytes.
 */
struct SwarmNotNoRdmaResult {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note a move request without moving bytes.
 * Order, first match wins: an empty link_id is LINK. want_move is
 * ENGINE_ABSENT. Otherwise the note is NOTED and err is clear.
 * moved and bytes_moved stay false on every path.
 * Missing RDMA moves no bytes.
 */
SwarmNotNoRdmaResult SwarmNoteNotNoRdma(const SwarmNotNoRdma& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORDMA_H
