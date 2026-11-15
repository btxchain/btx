// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCURRENCYBTX2_H
#define BTX_MODELNET_SWARM_NOTNOCURRENCYBTX2_H

#include <string>

namespace modelnet {

/**
 * A local note about one currency. quote_id names the quote.
 * want_rename asks this note to rename that currency.
 *
 * The currency stays BTX. renamed stays false on every path.
 */
struct SwarmNotNoCurrencyBtx2 {
    std::string quote_id;
    bool want_rename{false};
};

/**
 * Outcome of noting a currency. renamed stays false on every path.
 * The currency stays BTX.
 */
struct SwarmNotNoCurrencyBtx2Result {
    std::string code;
    bool renamed{false};
};

/**
 * Note a currency without renaming it.
 * Order, first match wins: an empty quote_id is QUOTE. want_rename is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * renamed stays false on every path. The currency stays BTX.
 */
SwarmNotNoCurrencyBtx2Result SwarmNoteNotNoCurrencyBtx2(const SwarmNotNoCurrencyBtx2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCURRENCYBTX2_H
