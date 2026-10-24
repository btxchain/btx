// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_H

#include <modelnet/swarm_onechannel/codes.h>
#include <modelnet/swarm_onechannel/flags.h>
#include <modelnet/swarm_onechannel/ledger.h>
#include <modelnet/swarm_onechannel/limits.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process one-channel book.
 * Reserve stores one channel id. BindPool binds many pools to that same id.
 * Fund marks a bound pool only when refund_bound is true.
 * Open always refuses. A reserved channel id is not a network open.
 * Quote stores usd text for a bound pool and reports NOT_BALANCE.
 * This plane does not open a network channel, broadcast, or move atoms.
 * network_opened() stays false. broadcast() stays false. launched() stays false.
 * gpu() stays false. atoms_moved() stays 0. automatic_spend() stays "0".
 * There is no method that sets those live.
 */
class SwarmOneChannel {
public:
    /**
     * Empty channel is CHANNEL and stores nothing.
     * The first non-empty channel id is stored and returns true.
     * The same id again is REPLAY and keeps it.
     * A different id is NOT_OPENED and does not replace the first id.
     * network_opened() stays false.
     */
    bool Reserve(const std::string& channel, std::string& err);

    /**
     * Empty pool is POOL and stores nothing.
     * No reserved channel is CHANNEL and stores nothing.
     * The first bind of a pool returns true.
     * The same pool again is REPLAY.
     * A different pool binds to the same single channel and returns true.
     */
    bool BindPool(const std::string& pool, std::string& err);

    /**
     * Unknown pool is POOL and stays unfunded.
     * refund_bound false is FUNDING. The pool stays unfunded and holds_money stays false
     * when it was not already funded.
     * refund_bound true marks that pool funded and holds_money becomes true.
     * Other pools are unchanged. broadcast() stays false. atoms_moved() stays 0.
     */
    bool Fund(const std::string& pool, bool refund_bound, std::string& err);

    /**
     * Always return false with NOT_OPENED.
     * network_opened() stays false. A reserved channel id is not a network open.
     */
    bool Open(std::string& err);

    /**
     * Unknown pool is POOL.
     * Empty usd is QUOTE and stores nothing.
     * A non-empty usd string is stored and the call returns false with NOT_BALANCE.
     * The quote does not change holds_money(pool) or any atom balance.
     */
    bool Quote(const std::string& pool, const std::string& usd, std::string& err);

    std::string channel_id() const;
    std::size_t pool_count() const;
    bool bound(const std::string& pool) const;
    bool funded(const std::string& pool) const;
    bool holds_money(const std::string& pool) const;
    std::string quote_of(const std::string& pool) const;
    bool network_opened() const;
    bool broadcast() const;
    bool launched() const;
    bool gpu() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;

private:
    SwarmOneChannelLedger m_ledger;
    SwarmOneChannelFlags m_flags;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_H
