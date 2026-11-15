// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_LEDGER_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_LEDGER_H

#include <modelnet/swarm_flagship/catalog.h>
#include <modelnet/swarm_flagship/slot.h>

#include <array>
#include <cstddef>
#include <optional>
#include <string>

namespace modelnet {

/**
 * Evidence ids for the thirteen flagship stages, in catalog order.
 * commit writes only into an empty cell whose earlier cells are full,
 * and it will not replace an id. clear_from drops that stage and every
 * later stage. Earlier stages stay. The book does not pass a stage.
 */
class SwarmFlagshipLedger {
public:
    bool recorded(std::size_t index) const;
    std::string evidence(std::size_t index) const;

    /** True when any stage before index has no evidence. */
    bool earlier_missing(std::size_t index) const;

    /**
     * Store evidence at index when the prefix before it is full and the
     * cell is empty. Returns false without writing when the index is
     * outside the catalog, an earlier cell is empty, the evidence is
     * empty, or the cell already holds an id.
     */
    bool commit(std::size_t index, const std::string& evidence);

    /** Drop evidence at index and at every later stage. */
    void clear_from(std::size_t index);

    /** First stage with no evidence, or empty when all thirteen are recorded. */
    std::optional<std::size_t> next_open() const;

private:
    /** True when a recorded stage never follows an empty stage. */
    bool prefix_closed() const;

    std::array<SwarmFlagshipSlot, SwarmFlagshipCatalog::count> m_slots{};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_LEDGER_H
