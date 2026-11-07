// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_researchkey.h>

namespace modelnet {

SwarmResearchKeyResult SwarmNoteResearchKey(const SwarmResearchKey& key, std::string& err)
{
    SwarmResearchKeyResult result;
    result.spend_armed = false;
    if (key.key_id.empty()) {
        result.spend_armed = false;
        result.code = "KEY";
        err = "KEY";
        return result;
    }
    // A research key does not receive a spend key. Nothing is signed.
    if (key.research_key && key.want_spend) {
        result.spend_armed = false;
        result.code = "RESEARCH";
        err = "RESEARCH";
        return result;
    }
    if (key.want_spend) {
        result.spend_armed = false;
        result.code = "SPEND_REFUSED";
        err = "SPEND_REFUSED";
        return result;
    }
    result.spend_armed = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
