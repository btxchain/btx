// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/rollback.h>

#include <modelnet/swarm_flagship/catalog.h>
#include <modelnet/swarm_flagship/codes.h>
#include <modelnet/swarm_flagship/ledger.h>

#include <cstddef>
#include <optional>
#include <string>

namespace modelnet {

bool SwarmFlagshipRollback::apply(SwarmFlagshipLedger& ledger, const std::string& stage, std::string& err) const
{
    const std::optional<std::size_t> found = SwarmFlagshipCatalog::index(stage);
    if (!found.has_value()) {
        return SwarmFlagshipRefuse(err, kSwarmFlagshipStage);
    }
    ledger.clear_from(*found);
    return SwarmFlagshipAccept(err);
}

} // namespace modelnet
