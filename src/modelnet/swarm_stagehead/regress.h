// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STAGEHEAD_REGRESS_H
#define BITCOIN_MODELNET_SWARM_STAGEHEAD_REGRESS_H

#include <modelnet/swarm_stagehead/active.h>
#include <modelnet/swarm_stagehead/memory.h>

#include <string>

namespace modelnet {

/**
 * Restores the remembered previous id once, by the same restore rollback uses.
 * Rollback and regress share that one memory. Either call consumes it.
 * A second regress finds nothing remembered and is ROLLBACK.
 */
class SwarmStageRegress {
public:
    bool Apply(SwarmStageActive& active, SwarmStageMemory& memory, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STAGEHEAD_REGRESS_H
