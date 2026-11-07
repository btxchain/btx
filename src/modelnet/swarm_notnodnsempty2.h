// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODNSEMPTY2_H
#define BTX_MODELNET_SWARM_NOTNODNSEMPTY2_H

#include <string>

namespace modelnet {

/**
 * A local note about one DNS seed list. want_add asks this note to add it.
 *
 * The DNS seed list stays empty. Adding to it is refused.
 * added stays false on every path.
 */
struct SwarmNotNoDnsEmpty2 {
    std::string list_id;
    bool want_add{false};
};

/**
 * Outcome of noting a DNS seed list. added stays false on every path.
 * The DNS seed list stays empty. Adding to it is refused.
 */
struct SwarmNotNoDnsEmpty2Result {
    std::string code;
    bool added{false};
};

/**
 * Note a DNS seed list without adding to it.
 * Order, first match wins: an empty list_id is LIST.
 * want_add is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * added stays false on every path.
 * The DNS seed list stays empty. Adding to it is refused.
 */
SwarmNotNoDnsEmpty2Result SwarmNoteNotNoDnsEmpty2(const SwarmNotNoDnsEmpty2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODNSEMPTY2_H
