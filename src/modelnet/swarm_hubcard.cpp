// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hubcard.h>

namespace modelnet {

SwarmHubCardResult SwarmNoteHubCard(const SwarmHubCard& card, std::string& err)
{
    // A hub card is not lineage authority.
    SwarmHubCardResult result;
    result.trusted = false;
    if (card.card_id.empty()) {
        result.code = "CARD";
        result.trusted = false;
        err = "CARD";
        return result;
    }
    if (card.want_trust) {
        result.code = "HELD";
        result.trusted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.trusted = false;
    err.clear();
    return result;
}

} // namespace modelnet
