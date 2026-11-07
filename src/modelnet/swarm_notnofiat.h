// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFIAT_H
#define BTX_MODELNET_SWARM_NOTNOFIAT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one fiat quote. want_balance asks this note to treat
 * that quote as a BTX balance.
 *
 * A fiat quote is not a BTX balance. booked stays false and atoms stays
 * 0 on every path.
 */
struct SwarmNotNoFiat {
    std::string quote_id;
    bool want_balance{false};
};

/**
 * Outcome of noting a fiat quote. booked stays false and atoms stays 0
 * on every path. A fiat quote is not a BTX balance.
 */
struct SwarmNotNoFiatResult {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

/**
 * Note a fiat quote without booking it as a BTX balance or moving atoms.
 * Order, first match wins: an empty quote_id is QUOTE. want_balance is
 * NOT_BALANCE. Otherwise the note is NOTED and err is clear.
 * booked stays false and atoms stays 0 on every path.
 * A fiat quote is not a BTX balance.
 */
SwarmNotNoFiatResult SwarmNoteNotNoFiat(const SwarmNotNoFiat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFIAT_H
