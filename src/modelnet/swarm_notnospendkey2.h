// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSPENDKEY2_H
#define BTX_MODELNET_SWARM_NOTNOSPENDKEY2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one key. research marks a research key.
 * want_arm asks this note to arm a spend.
 *
 * A research key is not a spend key.
 * armed stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoSpendKey2 {
    std::string key_id;
    bool research{false};
    bool want_arm{false};
};

/**
 * Outcome of noting a key. armed stays false and atoms stays 0 on
 * every path: a research key is not a spend key.
 */
struct SwarmNotNoSpendKey2Result {
    std::string code;
    bool armed{false};
    int64_t atoms{0};
};

/**
 * Note a key without arming a spend.
 * Order, first match wins: an empty key_id is KEY.
 * If research is true, the note is NOT_SPEND even when want_arm is false.
 * want_arm is HELD. Otherwise the note is NOTED and err is cleared.
 * armed stays false and atoms stays 0 on every path. A research key is
 * not a spend key.
 */
SwarmNotNoSpendKey2Result SwarmNoteNotNoSpendKey2(const SwarmNotNoSpendKey2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSPENDKEY2_H
