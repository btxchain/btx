// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STAGEHEAD_ROLLBACK_H
#define BITCOIN_MODELNET_SWARM_STAGEHEAD_ROLLBACK_H

#include <modelnet/swarm_stagehead/active.h>
#include <modelnet/swarm_stagehead/memory.h>

#include <string>

namespace modelnet {

/**
 * Restores the remembered previous id once, then clears that memory.
 * Nothing remembered is ROLLBACK and the active id stays.
 * Restore does not mine, broadcast, or spend. The staged slot is not an
 * argument, so a candidate sitting in that slot stays there.
 */
class SwarmStageRollback {
public:
    bool Restore(SwarmStageActive& active, SwarmStageMemory& memory, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STAGEHEAD_ROLLBACK_H
