// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FIATQUOTE_H
#define BTX_MODELNET_SWARM_FIATQUOTE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of a fiat quote. currency must be exactly "BTX" for the
 * quote to be a BTX note. want_balance asks this note to credit a
 * balance.
 *
 * Nothing is credited and nothing is broadcast. balance_credited stays
 * false on every path. A fiat quote is not a BTX balance. No hostnames
 * or IPs are used.
 */
struct SwarmFiatQuoteRequest {
    std::string quote_id;
    std::string currency;
    int64_t atoms{0};
    bool want_balance{false};
};

/**
 * Outcome of noting a fiat quote. balance_credited stays false on every
 * path: nothing is credited and nothing is broadcast.
 */
struct SwarmFiatQuoteResult {
    bool balance_credited{false};
    std::string code;
};

/**
 * Note a fiat quote without crediting a balance.
 * Order, first match wins: empty quote_id, empty currency, or atoms < 0
 * is QUOTE. A currency that is not exactly "BTX" is NOT_BTX, even when
 * want_balance is true. A fiat quote is not a BTX balance. want_balance
 * is HELD and err is clear. Otherwise the note is NOTED and err is clear.
 * balance_credited stays false on every path. Nothing is credited and
 * nothing is broadcast.
 */
SwarmFiatQuoteResult SwarmNoteFiatQuote(const SwarmFiatQuoteRequest& quote, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FIATQUOTE_H
