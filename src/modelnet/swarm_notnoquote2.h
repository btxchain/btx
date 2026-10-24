// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQUOTE2_H
#define BTX_MODELNET_SWARM_NOTNOQUOTE2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one quote. fiat marks the quote as fiat.
 * want_book asks this note to book it.
 *
 * A fiat quote is not a BTX balance.
 * booked stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoQuote2 {
    std::string quote_id;
    bool fiat{false};
    bool want_book{false};
};

/**
 * Outcome of noting a quote. booked stays false and atoms stays 0 on
 * every path: a fiat quote is not a BTX balance.
 */
struct SwarmNotNoQuote2Result {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

/**
 * Note a quote without booking it as a BTX balance or moving atoms.
 * Order, first match wins: an empty quote_id is QUOTE.
 * If fiat is true, the note is NOT_BALANCE even when want_book is false.
 * want_book is HELD. Otherwise the note is NOTED and err is cleared.
 * booked stays false and atoms stays 0 on every path. A fiat quote is
 * not a BTX balance.
 */
SwarmNotNoQuote2Result SwarmNoteNotNoQuote2(const SwarmNotNoQuote2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQUOTE2_H
