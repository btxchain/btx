// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/decide.h>

#include <modelnet/swarm_flagship/catalog.h>
#include <modelnet/swarm_flagship/ledger.h>

#include <cstddef>
#include <optional>
#include <string>

namespace modelnet {

SwarmFlagshipDecision SwarmFlagshipDecide(const SwarmFlagshipLedger& ledger,
                                          const std::string& stage,
                                          const std::string& evidence)
{
    const std::optional<std::size_t> found = SwarmFlagshipCatalog::index(stage);
    if (!found.has_value()) {
        return SwarmFlagshipDecision{SwarmFlagshipRecordOutcome::Stage, 0};
    }
    if (evidence.empty()) {
        return SwarmFlagshipDecision{SwarmFlagshipRecordOutcome::Evidence, *found};
    }
    if (ledger.earlier_missing(*found)) {
        return SwarmFlagshipDecision{SwarmFlagshipRecordOutcome::Order, *found};
    }
    if (ledger.recorded(*found)) {
        if (ledger.evidence(*found) == evidence) {
            return SwarmFlagshipDecision{SwarmFlagshipRecordOutcome::Replay, *found};
        }
        return SwarmFlagshipDecision{SwarmFlagshipRecordOutcome::Conflict, *found};
    }
    return SwarmFlagshipDecision{SwarmFlagshipRecordOutcome::Store, *found};
}

} // namespace modelnet
