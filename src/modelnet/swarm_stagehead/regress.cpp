// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/regress.h>

#include <modelnet/swarm_stagehead/rollback.h>

namespace modelnet {

bool SwarmStageRegress::Apply(SwarmStageActive& active, SwarmStageMemory& memory, std::string& err) const
{
    return SwarmStageRollback{}.Restore(active, memory, err);
}

} // namespace modelnet
