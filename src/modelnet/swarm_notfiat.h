// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFIAT_H
#define BTX_MODELNET_SWARM_NOTFIAT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one fiat quote. want_count asks this note to count
 * that quote as a BTX balance.
 *
 * A fiat quote is not a BTX balance. counted stays false and atoms stays
 * 0 on every path.
 */
struct SwarmNotFiat {
    std::string quote_id;
    bool want_count{false};
};

/**
 * Outcome of noting a fiat quote. counted stays false and atoms stays 0
 * on every path. A fiat quote is not a BTX balance.
 */
struct SwarmNotFiatResult {
    std::string code;
    bool counted{false};
    int64_t atoms{0};
};

/**
 * Note a fiat quote without counting it as a BTX balance or moving atoms.
 * Order, first match wins: an empty quote_id is QUOTE. want_count is
 * NOT_BALANCE. Otherwise the note is NOTED and err is clear.
 * counted stays false and atoms stays 0 on every path.
 * A fiat quote is not a BTX balance.
 */
SwarmNotFiatResult SwarmNoteNotFiat(const SwarmNotFiat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFIAT_H
