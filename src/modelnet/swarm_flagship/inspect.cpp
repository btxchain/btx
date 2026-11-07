// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/inspect.h>

#include <modelnet/swarm_flagship/catalog.h>
#include <modelnet/swarm_flagship/ledger.h>

#include <cstddef>
#include <optional>
#include <string>

namespace modelnet {

bool SwarmFlagshipInspect::recorded(const SwarmFlagshipLedger& ledger, const std::string& stage)
{
    const std::optional<std::size_t> found = SwarmFlagshipCatalog::index(stage);
    if (!found.has_value()) {
        return false;
    }
    return ledger.recorded(*found);
}

std::string SwarmFlagshipInspect::evidence(const SwarmFlagshipLedger& ledger, const std::string& stage)
{
    const std::optional<std::size_t> found = SwarmFlagshipCatalog::index(stage);
    if (!found.has_value()) {
        return std::string{};
    }
    return ledger.evidence(*found);
}

std::string SwarmFlagshipInspect::next_stage(const SwarmFlagshipLedger& ledger)
{
    const std::optional<std::size_t> found = ledger.next_open();
    if (!found.has_value()) {
        return std::string{};
    }
    const char* stage = SwarmFlagshipCatalog::name(*found);
    if (stage == nullptr) {
        return std::string{};
    }
    return std::string{stage};
}

} // namespace modelnet
