// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEARNED_H
#define BTX_MODELNET_SWARM_NOTNOEARNED_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one earned row. row_id names the row.
 * coordinator_gone marks the coordinator as gone. want_drop asks this
 * note to drop the row.
 *
 * Earned rows stay when the coordinator is gone and nothing is paid or
 * dropped. dropped stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoEarned {
    std::string row_id;
    bool coordinator_gone{false};
    bool want_drop{false};
};

/**
 * Outcome of noting an earned row. dropped stays false and atoms stays 0
 * on every path. Earned rows stay when the coordinator is gone and
 * nothing is paid or dropped.
 */
struct SwarmNotNoEarnedResult {
    std::string code;
    bool dropped{false};
    int64_t atoms{0};
};

/**
 * Note an earned row without paying or dropping it. Order, first match
 * wins: an empty row_id is ROW. If coordinator_gone is true, the note is
 * KEPT even when want_drop is false. want_drop is KEPT. Otherwise the
 * note is NOTED and err is cleared. dropped stays false and atoms stays
 * 0 on every path. Earned rows stay when the coordinator is gone and
 * nothing is paid or dropped.
 */
SwarmNotNoEarnedResult SwarmNoteNotNoEarned(const SwarmNotNoEarned& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEARNED_H
