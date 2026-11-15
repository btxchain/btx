// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHFCARD2_H
#define BTX_MODELNET_SWARM_NOTNOHFCARD2_H

#include <string>

namespace modelnet {

/**
 * A local note about one hub card. want_trust asks this note to hold
 * lineage trust.
 *
 * A hub card is not lineage authority. trusted stays false on every path.
 */
struct SwarmNotNoHfCard2 {
    std::string card_id;
    bool want_trust{false};
};

/**
 * Outcome of noting a hub card. trusted stays false: a hub card is not
 * lineage authority.
 */
struct SwarmNotNoHfCard2Result {
    std::string code;
    bool trusted{false};
};

/**
 * Note a hub card without granting lineage authority.
 * Order, first match wins: an empty card_id is CARD. want_trust is HELD.
 * Otherwise the note is NOTED and err is cleared. trusted stays false
 * on every path. A hub card is not lineage authority.
 */
SwarmNotNoHfCard2Result SwarmNoteNotNoHfCard2(const SwarmNotNoHfCard2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHFCARD2_H
