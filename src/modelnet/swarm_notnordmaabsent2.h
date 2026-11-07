// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORDMAABSENT2_H
#define BTX_MODELNET_SWARM_NOTNORDMAABSENT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. rdma_absent says the RDMA adapter is missing.
 * want_move asks this note to move bytes.
 *
 * A missing RDMA adapter moves no bytes.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoRdmaAbsent2 {
    std::string engine_id;
    bool rdma_absent{false};
    bool want_move{false};
};

/**
 * Outcome of noting a move request. moved and bytes_moved stay false on
 * every path: a missing RDMA adapter moves no bytes.
 */
struct SwarmNotNoRdmaAbsent2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note a move request without moving bytes.
 * Order, first match wins: an empty engine_id is ENGINE. rdma_absent true
 * is ENGINE_ABSENT even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path.
 * A missing RDMA adapter moves no bytes.
 */
SwarmNotNoRdmaAbsent2Result SwarmNoteNotNoRdmaAbsent2(const SwarmNotNoRdmaAbsent2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORDMAABSENT2_H
