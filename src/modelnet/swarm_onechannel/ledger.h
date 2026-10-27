// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_LEDGER_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_LEDGER_H

#include <modelnet/swarm_onechannel/record.h>

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory book of one channel and the pools bound to it.
 * Reserve stores the first channel id and refuses a second id.
 * BindPool attaches every accepted pool to that same id.
 * Fund marks one bound pool when refund_bound is true and leaves the others alone.
 * Open never changes the seat. Quote stores usd text and does not move atoms.
 * The ledger has no network-open flag and no broadcast flag.
 */
class SwarmOneChannelLedger {
public:
    /**
     * Store the first non-empty channel id.
     * An empty channel is CHANNEL and stores nothing.
     * The same id again is REPLAY and keeps the first id.
     * A different id is NOT_OPENED and does not replace the first id.
     */
    bool Reserve(const std::string& channel, std::string& err);

    /**
     * Bind pool to the reserved channel.
     * An empty pool is POOL and stores nothing.
     * No reserved channel is CHANNEL and stores nothing.
     * The same pool again is REPLAY.
     * A different pool binds to the same channel and returns true.
     */
    bool BindPool(const std::string& pool, std::string& err);

    /**
     * Mark one bound pool funded when refund_bound is true.
     * An unknown pool is POOL and stays unfunded.
     * refund_bound false is FUNDING. That pool is not marked funded.
     * Other pools are left as they were. Atoms on the row stay zero.
     */
    bool Fund(const std::string& pool, bool refund_bound, std::string& err);

    /**
     * Always NOT_OPENED.
     * A reserved channel id is not a network open. The seat is not changed.
     */
    bool Open(std::string& err);

    /**
     * Store a non-empty usd quote for a bound pool and return false with NOT_BALANCE.
     * An unknown pool is POOL and stores nothing.
     * An empty usd is QUOTE and stores nothing.
     * holds_money and atoms are left as they were.
     */
    bool Quote(const std::string& pool, const std::string& usd, std::string& err);

    /** Reserved channel id, or empty when no channel has been stored. */
    std::string channel_id() const;

    /** How many pools are bound to the reserved channel. */
    std::size_t pool_count() const;

    /** True when pool is bound to the reserved channel. */
    bool bound(const std::string& pool) const;

    /** True when pool was marked funded. */
    bool funded(const std::string& pool) const;

    /** True when pool was marked funded and therefore holds money. */
    bool holds_money(const std::string& pool) const;

    /** Stored usd quote, or empty when pool has no quote. */
    std::string quote_of(const std::string& pool) const;

private:
    const SwarmOneChannelPool* FindBound(const std::string& pool) const;

    SwarmOneChannelSeat m_seat;
    std::map<std::string, SwarmOneChannelPool> m_pools;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_LEDGER_H
