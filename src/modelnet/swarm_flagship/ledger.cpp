// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/ledger.h>

#include <modelnet/swarm_flagship/catalog.h>
#include <modelnet/swarm_flagship/slot.h>

#include <cstddef>
#include <optional>
#include <string>

namespace modelnet {

bool SwarmFlagshipLedger::recorded(std::size_t index) const
{
    if (index >= SwarmFlagshipCatalog::count) {
        return false;
    }
    return m_slots[index].recorded();
}

std::string SwarmFlagshipLedger::evidence(std::size_t index) const
{
    if (index >= SwarmFlagshipCatalog::count) {
        return std::string{};
    }
    return m_slots[index].evidence();
}

bool SwarmFlagshipLedger::prefix_closed() const
{
    bool saw_blank = false;
    for (const SwarmFlagshipSlot& slot : m_slots) {
        if (!slot.recorded()) {
            saw_blank = true;
            continue;
        }
        if (saw_blank) {
            return false;
        }
    }
    return true;
}

bool SwarmFlagshipLedger::earlier_missing(std::size_t index) const
{
    if (index > SwarmFlagshipCatalog::count) {
        return true;
    }
    if (!prefix_closed()) {
        return true;
    }
    for (std::size_t i = 0; i < index; ++i) {
        if (!m_slots[i].recorded()) {
            return true;
        }
    }
    return false;
}

bool SwarmFlagshipLedger::commit(std::size_t index, const std::string& evidence)
{
    if (index >= SwarmFlagshipCatalog::count) {
        return false;
    }
    if (earlier_missing(index)) {
        return false;
    }
    return m_slots[index].store(evidence);
}

void SwarmFlagshipLedger::clear_from(std::size_t index)
{
    if (index >= SwarmFlagshipCatalog::count) {
        return;
    }
    for (std::size_t i = index; i < SwarmFlagshipCatalog::count; ++i) {
        m_slots[i].clear();
    }
}

std::optional<std::size_t> SwarmFlagshipLedger::next_open() const
{
    for (std::size_t i = 0; i < SwarmFlagshipCatalog::count; ++i) {
        if (!m_slots[i].recorded()) {
            return i;
        }
    }
    return std::nullopt;
}

} // namespace modelnet
