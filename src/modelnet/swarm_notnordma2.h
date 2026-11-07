// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORDMA2_H
#define BTX_MODELNET_SWARM_NOTNORDMA2_H

#include <string>

namespace modelnet {

/**
 * A local note about one adapter. present says the adapter is here.
 * want_move asks this note to move bytes.
 *
 * Missing RDMA moves no bytes.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoRdma2 {
    std::string adapter_id;
    bool present{false};
    bool want_move{false};
};

/**
 * Outcome of noting a move request. moved and bytes_moved stay false on
 * every path: missing RDMA moves no bytes.
 */
struct SwarmNotNoRdma2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note a move request without moving bytes.
 * Order, first match wins: an empty adapter_id is ADAPTER. present false
 * is ENGINE_ABSENT even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path.
 * Missing RDMA moves no bytes.
 */
SwarmNotNoRdma2Result SwarmNoteNotNoRdma2(const SwarmNotNoRdma2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORDMA2_H
