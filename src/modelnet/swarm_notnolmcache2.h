// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLMCACHE2_H
#define BTX_MODELNET_SWARM_NOTNOLMCACHE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one adapter. cuda_ops records whether compiled
 * LMCache CUDA ops are present. want_move asks this note to move bytes.
 *
 * Missing LMCache CUDA ops move no bytes.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoLmcache2 {
    std::string adapter_id;
    bool cuda_ops{false};
    bool want_move{false};
};

/**
 * Outcome of noting an adapter. moved and bytes_moved stay false on
 * every path: missing LMCache CUDA ops move no bytes.
 */
struct SwarmNotNoLmcache2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note an adapter without moving bytes.
 * Order, first match wins: an empty adapter_id is ADAPTER. cuda_ops
 * false is ENGINE_ABSENT even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path. Missing LMCache CUDA
 * ops move no bytes.
 */
SwarmNotNoLmcache2Result SwarmNoteNotNoLmcache2(const SwarmNotNoLmcache2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLMCACHE2_H
