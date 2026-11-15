// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHFLINEAGE2_H
#define BTX_MODELNET_SWARM_NOTNOHFLINEAGE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one hub model card. hub_card marks the note as a
 * hub model card. want_trust asks this note to hold lineage trust.
 *
 * A hub model card is not lineage authority. trusted stays false on
 * every path.
 */
struct SwarmNotNoHfLineage2 {
    std::string model_id;
    bool hub_card{false};
    bool want_trust{false};
};

/**
 * Outcome of noting a hub model card. trusted stays false: a hub model
 * card is not lineage authority.
 */
struct SwarmNotNoHfLineage2Result {
    std::string code;
    bool trusted{false};
};

/**
 * Note a hub model card without granting lineage authority.
 * Order, first match wins: an empty model_id is MODEL. hub_card is
 * NOT_LINEAGE even when want_trust is false. want_trust is HELD.
 * Otherwise the note is NOTED and err is cleared. trusted stays false
 * on every path. A hub model card is not lineage authority.
 */
SwarmNotNoHfLineage2Result SwarmNoteNotNoHfLineage2(const SwarmNotNoHfLineage2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHFLINEAGE2_H
