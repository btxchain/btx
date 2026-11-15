// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_H

#include <modelnet/swarm_quotefiat/atoms.h>
#include <modelnet/swarm_quotefiat/balance.h>
#include <modelnet/swarm_quotefiat/book.h>
#include <modelnet/swarm_quotefiat/quiet.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Fiat-quote plane.
 * A fiat quote is not a BTX balance. No atoms move.
 *
 * Quote stores a non-empty usd and returns false with NOT_BALANCE.
 * An empty usd is QUOTE and stores nothing.
 * A second Quote of the same usd is REPLAY and keeps the first quote.
 * QUOTE is decided before REPLAY.
 *
 * atoms() stays 0. usd_is_balance() stays false.
 * broadcast() stays false. mined() stays false.
 * bytes_moved() stays 0. automatic_spend() stays "0".
 */
class SwarmQuoteFiat {
public:
    /**
     * Quote one usd string.
     * An empty usd is QUOTE and stores nothing.
     * A non-empty usd is stored and the call returns false with err
     * NOT_BALANCE. atoms() stays 0. usd_is_balance() stays false.
     * A second Quote of the same usd is REPLAY and keeps the first quote.
     * atoms() stays 0.
     */
    bool Quote(const std::string& usd, std::string& err);

    /** True when Quote kept this usd. */
    bool quoted(const std::string& usd) const;

    /** The kept quote text, or empty when usd was not stored. */
    std::string stored_usd(const std::string& usd) const;

    /** Number of kept quotes. */
    std::size_t quote_count() const;

    /** Stays 0. A quote does not credit atoms. */
    int64_t atoms() const;

    /** Stays false. A stored usd is not a balance. */
    bool usd_is_balance() const;

    bool broadcast() const;
    bool mined() const;
    int64_t bytes_moved() const;
    std::string automatic_spend() const;

private:
    SwarmQuoteFiatBook m_book;
    SwarmQuoteFiatAtoms m_atoms;
    SwarmQuoteFiatBalance m_balance;
    SwarmQuoteFiatQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_H
