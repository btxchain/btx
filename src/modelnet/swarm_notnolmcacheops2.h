// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLMCACHEOPS2_H
#define BTX_MODELNET_SWARM_NOTNOLMCACHEOPS2_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. cuda_ops_absent records whether compiled
 * LMCache CUDA ops are absent. want_move asks this note to move bytes.
 *
 * Missing LMCache CUDA ops move no bytes.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoLmcacheOps2 {
    std::string engine_id;
    bool cuda_ops_absent{false};
    bool want_move{false};
};

/**
 * Outcome of noting an engine. moved and bytes_moved stay false on
 * every path: missing LMCache CUDA ops move no bytes.
 */
struct SwarmNotNoLmcacheOps2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note an engine without moving bytes.
 * Order, first match wins: an empty engine_id is ENGINE. cuda_ops_absent
 * is ENGINE_ABSENT even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path. Missing LMCache CUDA
 * ops move no bytes.
 */
SwarmNotNoLmcacheOps2Result SwarmNoteNotNoLmcacheOps2(const SwarmNotNoLmcacheOps2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLMCACHEOPS2_H
