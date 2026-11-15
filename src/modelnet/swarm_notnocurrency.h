// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCURRENCY_H
#define BTX_MODELNET_SWARM_NOTNOCURRENCY_H

#include <string>

namespace modelnet {

/**
 * A local note about one currency. want_rename asks this note to rename
 * that currency.
 *
 * The currency stays BTX. renamed and booked stay false on every path.
 */
struct SwarmNotNoCurrency {
    std::string code_id;
    bool want_rename{false};
};

/**
 * Outcome of noting a currency. renamed and booked stay false on every
 * path: the currency stays BTX.
 */
struct SwarmNotNoCurrencyResult {
    std::string code;
    bool renamed{false};
    bool booked{false};
};

/**
 * Note a currency without renaming it.
 * Order, first match wins: an empty code_id is CODE. A code_id that is
 * not exactly BTX is FIXED even when want_rename is false. want_rename is
 * FIXED. Otherwise the note is NOTED and err is clear.
 * renamed and booked stay false on every path. The currency stays BTX.
 */
SwarmNotNoCurrencyResult SwarmNoteNotNoCurrency(const SwarmNotNoCurrency& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCURRENCY_H
