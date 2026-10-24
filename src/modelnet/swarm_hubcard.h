// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_HUBCARD_H
#define BTX_MODELNET_SWARM_HUBCARD_H

#include <string>

namespace modelnet {

/**
 * A hub-card record. A hub card is not lineage authority.
 * It does not grant trust. trusted stays false on every path.
 */
struct SwarmHubCard {
    std::string card_id;
    bool want_trust{false};
};

/**
 * Outcome of noting a hub card. trusted stays false on every path.
 */
struct SwarmHubCardResult {
    std::string code;
    bool trusted{false};
};

/**
 * Note a hub card. Empty card_id is CARD. want_trust is HELD.
 * Otherwise the note is NOTED and err is clear. trusted stays false
 * on every path. A hub card is not lineage authority.
 */
SwarmHubCardResult SwarmNoteHubCard(const SwarmHubCard& card, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_HUBCARD_H
