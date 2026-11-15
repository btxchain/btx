// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTAUTOSPEND_H
#define BTX_MODELNET_SWARM_NOTAUTOSPEND_H

#include <string>

namespace modelnet {

/**
 * A local note about one wallet. automatic_spend_atoms is the spend
 * amount this note would claim. want_spend asks this note to spend.
 *
 * automatic_spend_atoms stays "0" until an operator wallet signs a
 * bounded mandate. This note spends nothing. spent and broadcast stay
 * false on every path.
 */
struct SwarmNotAutospend {
    std::string wallet_id;
    std::string automatic_spend_atoms;
    bool want_spend{false};
};

/**
 * Outcome of noting an automatic spend. spent and broadcast stay false
 * on every path. automatic_spend_atoms stays "0" until an operator
 * wallet signs a bounded mandate. This note spends nothing.
 */
struct SwarmNotAutospendResult {
    std::string code;
    bool spent{false};
    bool broadcast{false};
};

/**
 * Note an automatic spend without spending or broadcasting. Order,
 * first match wins: an empty wallet_id is WALLET. automatic_spend_atoms
 * not exactly "0" is HELD even when want_spend is false. want_spend is
 * HELD. Otherwise the note is NOTED and err is clear. spent and
 * broadcast stay false on every path. automatic_spend_atoms stays "0"
 * until an operator wallet signs a bounded mandate. This note spends
 * nothing.
 */
SwarmNotAutospendResult SwarmNoteNotAutospend(const SwarmNotAutospend& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTAUTOSPEND_H
