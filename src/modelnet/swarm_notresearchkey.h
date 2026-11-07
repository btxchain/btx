// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTRESEARCHKEY_H
#define BTX_MODELNET_SWARM_NOTRESEARCHKEY_H

#include <string>

namespace modelnet {

/**
 * A local note about a research key. key_id names the key.
 * want_spend asks this note to issue a spend key.
 *
 * A research key never receives a spend key. spend_key and broadcast
 * stay false on every path.
 */
struct SwarmNotResearchKey {
    std::string key_id;
    bool want_spend{false};
};

/**
 * Outcome of noting a research key. spend_key and broadcast stay false
 * on every path: a research key never receives a spend key.
 */
struct SwarmNotResearchKeyResult {
    std::string code;
    bool spend_key{false};
    bool broadcast{false};
};

/**
 * Note a research key without issuing a spend key.
 * Order, first match wins: an empty key_id is KEY. want_spend is
 * NO_KEY. Otherwise the note is NOTED and err is clear.
 * spend_key and broadcast stay false on every path.
 * A research key never receives a spend key.
 */
SwarmNotResearchKeyResult SwarmNoteNotResearchKey(const SwarmNotResearchKey& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTRESEARCHKEY_H
