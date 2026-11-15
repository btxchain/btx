// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREORG2_H
#define BTX_MODELNET_SWARM_NOTNOREORG2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one transaction. reorg marks a reorg.
 * want_spend asks this note to spend.
 *
 * A reorg freezes the spend and pays nothing. spent stays false and
 * atoms stays 0 on every path.
 */
struct SwarmNotNoReorg2 {
    std::string tx_id;
    bool reorg{false};
    bool want_spend{false};
};

/**
 * Outcome of noting a transaction. spent stays false and atoms stays 0
 * on every path. A reorg freezes the spend and pays nothing.
 */
struct SwarmNotNoReorg2Result {
    std::string code;
    bool spent{false};
    int64_t atoms{0};
};

/**
 * Note a transaction without spending. Order, first match wins: an empty
 * tx_id is TX. If reorg is true, the note is FROZEN even when want_spend
 * is false. want_spend is HELD. Otherwise the note is NOTED and err is
 * cleared. spent stays false and atoms stays 0 on every path. A reorg
 * freezes the spend and pays nothing.
 */
SwarmNotNoReorg2Result SwarmNoteNotNoReorg2(const SwarmNotNoReorg2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREORG2_H
