// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSPEND02_H
#define BTX_MODELNET_SWARM_NOTNOSPEND02_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one wallet. want_arm asks this note to arm.
 *
 * Automatic spend stays zero until an operator wallet signs a bounded
 * mandate. armed stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoSpend02 {
    std::string wallet_id;
    bool want_arm{false};
};

/**
 * Outcome of noting a wallet. armed stays false and atoms stays 0 on
 * every path. Automatic spend stays zero until an operator wallet signs
 * a bounded mandate.
 */
struct SwarmNotNoSpend02Result {
    std::string code;
    bool armed{false};
    int64_t atoms{0};
};

/**
 * Note a wallet without arming a spend. Order, first match wins: an
 * empty wallet_id is WALLET. want_arm is HELD. Otherwise the note is
 * NOTED and err is cleared. armed stays false and atoms stays 0 on
 * every path. Automatic spend stays zero until an operator wallet signs
 * a bounded mandate.
 */
SwarmNotNoSpend02Result SwarmNoteNotNoSpend02(const SwarmNotNoSpend02& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSPEND02_H
