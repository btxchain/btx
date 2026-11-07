// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_EARNKEEP_H
#define BTX_MODELNET_SWARM_EARNKEEP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One earned row. row_id names the row. atoms is the earned amount.
 * coordinator_gone marks the coordinator as gone. want_drop asks to drop
 * the row. want_spend asks to spend it.
 *
 * An earned row stays when the coordinator is gone and is not spent.
 * dropped and spent stay false on every path.
 */
struct SwarmEarnKeep {
    std::string row_id;
    int64_t atoms{0};
    bool coordinator_gone{false};
    bool want_drop{false};
    bool want_spend{false};
};

/**
 * Outcome of keeping an earned row. dropped and spent stay false on every
 * path. An earned row stays when the coordinator is gone and is not spent.
 */
struct SwarmEarnKeepResult {
    std::string code;
    bool dropped{false};
    bool spent{false};
    int64_t atoms{0};
};

/**
 * Keep an earned row without spending, broadcasting, or mining.
 * Order, first match wins: an empty row_id is ROW with atoms 0. atoms
 * below zero is RANGE with atoms 0. coordinator_gone is STAYS and the
 * atoms are copied, even when want_drop is false. want_drop or want_spend
 * is HELD and the atoms are copied. Otherwise the row is NOTED, err is
 * cleared, and the atoms are copied. dropped and spent stay false on
 * every path. An earned row stays when the coordinator is gone and is
 * not spent.
 */
SwarmEarnKeepResult SwarmKeepEarned(const SwarmEarnKeep& row, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_EARNKEEP_H
