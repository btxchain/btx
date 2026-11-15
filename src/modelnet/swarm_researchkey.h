// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RESEARCHKEY_H
#define BTX_MODELNET_SWARM_RESEARCHKEY_H

#include <string>

namespace modelnet {

/**
 * A research-key note. key_id names the note. research_key marks a
 * research key. want_spend asks this note for a spend key.
 *
 * A research key does not receive a spend key. spend_armed stays false
 * on every path. Nothing is signed. No hostnames, IPs, or key bytes
 * are used.
 */
struct SwarmResearchKey {
    std::string key_id;
    bool research_key{false};
    bool want_spend{false};
};

/**
 * Outcome of noting a research key. spend_armed stays false: a research
 * key does not receive a spend key. Nothing is signed.
 */
struct SwarmResearchKeyResult {
    bool spend_armed{false};
    std::string code;
};

/**
 * Note a research key. Order, first match wins: an empty key_id is KEY.
 * research_key together with want_spend is RESEARCH. want_spend is
 * SPEND_REFUSED. Otherwise the result is NOTED and err is cleared.
 * spend_armed stays false on every path. A research key does not receive
 * a spend key. Nothing is signed.
 */
SwarmResearchKeyResult SwarmNoteResearchKey(const SwarmResearchKey& key, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_RESEARCHKEY_H
