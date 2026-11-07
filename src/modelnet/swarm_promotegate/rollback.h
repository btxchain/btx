// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_ROLLBACK_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_ROLLBACK_H

#include <modelnet/swarm_promotegate/active.h>
#include <modelnet/swarm_promotegate/memory.h>

#include <string>

namespace modelnet {

/**
 * Restores the remembered previous id once, then clears that memory.
 * Nothing remembered is ROLLBACK and the active id stays.
 * A second rollback finds nothing remembered and is ROLLBACK.
 * Restore does not mine or broadcast. The staged slot and the interrupt
 * flag are not arguments, so a candidate sitting in that slot stays there.
 */
class SwarmPromoteRollback {
public:
    bool Restore(SwarmPromoteActive& active, SwarmPromoteMemory& memory, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_ROLLBACK_H
