// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPREFETCH2_H
#define BTX_MODELNET_SWARM_NOTNOPREFETCH2_H

#include <string>

namespace modelnet {

/**
 * A prefetch note. A prefetch note moves no bytes.
 */
struct SwarmNotNoPrefetch2 {
    std::string transfer_id;
    bool want_prefetch{false};
};

/**
 * Outcome of a prefetch note. moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoPrefetch2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note a prefetch request without moving bytes.
 * An empty transfer_id is TRANSFER.
 * want_prefetch is HELD.
 * Otherwise the note is NOTED and err is clear.
 * moved and bytes_moved stay false on every path. A prefetch note moves no bytes.
 */
SwarmNotNoPrefetch2Result SwarmNoteNotNoPrefetch2(const SwarmNotNoPrefetch2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPREFETCH2_H
