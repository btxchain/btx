// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCURRENCY_H
#define BTX_MODELNET_SWARM_NOTCURRENCY_H

#include <string>

namespace modelnet {

/**
 * A local note about one currency. want_rename asks this note to rename
 * that currency.
 *
 * The currency stays BTX. renamed stays false on every path.
 */
struct SwarmNotCurrency {
    std::string unit_id;
    bool want_rename{false};
};

/**
 * Outcome of noting a currency. renamed stays false on every path:
 * the currency stays BTX.
 */
struct SwarmNotCurrencyResult {
    std::string code;
    bool renamed{false};
};

/**
 * Note a currency without renaming it.
 * Order, first match wins: an empty unit_id is UNIT. A unit_id that is
 * not exactly BTX is FIXED even when want_rename is false. want_rename is
 * FIXED. Otherwise the note is NOTED and err is clear.
 * renamed stays false on every path. The currency stays BTX.
 */
SwarmNotCurrencyResult SwarmNoteNotCurrency(const SwarmNotCurrency& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCURRENCY_H
