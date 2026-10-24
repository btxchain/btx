// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_BOOK_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_BOOK_H

#include <modelnet/swarm_quotefiat/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Fiat quotes stored by Quote, keyed by the usd text.
 * store refuses an empty usd and a usd already present.
 * A refused store leaves the first quote in place.
 * There is no method that writes atoms or marks a quote as a balance.
 */
class SwarmQuoteFiatBook {
public:
    bool contains(const std::string& usd) const;
    std::string usd_of(const std::string& usd) const;
    std::size_t size() const;

    /** Sum of atoms on every kept quote. Each quote is built with 0. */
    int64_t atoms() const;

    /** True when any kept quote is marked as a balance. None are. */
    bool usd_is_balance() const;

    /**
     * Store usd as a quote.
     * Refuses an empty usd and a usd already present. On refusal the
     * book is unchanged.
     */
    bool store(const std::string& usd);

private:
    std::map<std::string, SwarmQuoteFiatRecord> m_quotes;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_BOOK_H
