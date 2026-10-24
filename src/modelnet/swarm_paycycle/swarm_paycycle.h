// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYCYCLE_H
#define BITCOIN_MODELNET_SWARM_PAYCYCLE_H

#include <modelnet/swarm_paycycle/codes.h>
#include <modelnet/swarm_paycycle/collateral.h>
#include <modelnet/swarm_paycycle/obligations.h>
#include <modelnet/swarm_paycycle/pools.h>
#include <modelnet/swarm_paycycle/quotes.h>
#include <modelnet/swarm_paycycle/split.h>
#include <modelnet/swarm_paycycle/transfer.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process payment mesh with many pools.
 *
 * The scheduler has no spend key. It does not sign, broadcast, open a
 * channel on a network, or spend. automatic_spend() stays "0".
 * broadcast(), launched(), and gpu() stay false. atoms_moved() and
 * bytes_moved() stay 0. l1_transactions() stays 0.
 *
 * holds_money() is true only when some pool is funded. holds_money(pool)
 * is true only for that funded pool. An unfunded pool is never advertised
 * as holding money. A fiat quote is not a balance. Fund does not assign a
 * balance. Channel reserve adds in-memory balance. Escrow reserve does not.
 *
 * Accepted objectives are model-improvement, specialist-training,
 * inference-service, evaluation, and application.
 *
 * The pool id is the hex HASH256 of chain, lineage, nonce, objective, and
 * policy joined by one 0 byte. Raising the policy epoch stores a new id.
 * Obligations already stored on the old id stay on the old id.
 */
class SwarmPayCycle {
public:
    /**
     * Store an unfunded pool. Empty chain, lineage, or nonce is POOL.
     * Any other objective is OBJECTIVE. A second publish of the same id
     * is REPLAY. holds_money() stays false for the new pool.
     */
    bool Publish(const std::string& chain, const std::string& lineage, const std::string& nonce,
                 const std::string& objective, const std::string& policy, std::string& err);

    /**
     * Store a new unfunded pool id for new_policy. Unknown pool is POOL.
     * Empty new_policy is POLICY. The old pool and its obligations stay.
     * An id that already exists is REPLAY.
     */
    bool RaiseEpoch(const std::string& pool, const std::string& new_policy, std::string& err);

    /**
     * Store a caller-supplied ppm split. Parts must be >= 0 and sum to
     * 1000000. Otherwise SPLIT and the previous split stays. Not a tax.
     */
    bool Split(int64_t rollout, int64_t negative, int64_t reproduction, int64_t evaluation, int64_t challengers,
               int64_t milestone, std::string& err);

    /**
     * refund_bound true marks the pool funded. Unknown pool is POOL.
     * refund_bound false is FUNDING and does not fund or unfund.
     * Balance, atoms_moved(), and broadcast() stay as they were.
     */
    bool Fund(const std::string& pool, bool refund_bound, std::string& err);

    /**
     * Store a lease on a funded pool. Unknown or unfunded is FUNDING.
     * Empty work or worker is WORK. A duplicate work id on that pool is
     * REPLAY and does not change atoms.
     */
    bool Lease(const std::string& pool, const std::string& work, const std::string& worker, std::string& err);

    /**
     * profit-share is REFUSED. Any other label except work-payment is LABEL.
     * An unknown lease is WORK. work-payment marks the lease earned and
     * returns false with HELD. atoms_moved() stays 0. The earned row stays.
     */
    bool Pay(const std::string& pool, const std::string& work, const std::string& label, std::string& err);

    /**
     * Empty usd is QUOTE and stores nothing. Any other usd is stored and
     * returns false with NOT_BALANCE. The quote does not change a balance.
     */
    bool Quote(const std::string& pool, const std::string& usd, std::string& err);

    /**
     * Record escrow or channel collateral for one outpoint.
     * role defaults to channel. atoms below 1, an empty outpoint, or an
     * unknown role is COLLATERAL. An unknown pool is POOL. A second pool
     * for the same outpoint is OUTPOINT and stores nothing. The other role
     * on the same pool and outpoint is COLLATERAL_REUSE. The same role
     * again is REPLAY and does not add atoms. Channel adds atoms to the
     * pool balance. Escrow does not. After Freeze, this returns FROZEN.
     */
    bool Reserve(const std::string& pool, const std::string& outpoint, int64_t atoms, std::string& err,
                 const std::string& role = SWARM_PAYCYCLE_ROLE_CHANNEL);

    /**
     * Move atoms between funded in-memory balances. An unfunded side is
     * FUNDING. atoms below 1 is AMOUNT. A repeated payment_id is REPLAY.
     * A short balance is NEGATIVE and commits nothing. Success debits
     * from_pool, credits to_pool, and increases sequence by 1.
     * l1_transactions() stays 0. broadcast() stays false. After Freeze,
     * this returns FROZEN.
     */
    bool ApplyBatch(const std::string& from_pool, const std::string& to_pool, const std::string& payment_id,
                    int64_t atoms, std::string& err);

    /**
     * Count funded pools with a positive balance and remember that count.
     * Does not build one entry per payment. broadcast() stays false.
     */
    int64_t CloseTemplate();

    /** Set frozen() and return false with FREEZE. Earned rows stay. */
    bool Freeze(std::string& err);

    int64_t pool_count() const;
    bool funded(const std::string& pool) const;
    bool holds_money() const;
    bool holds_money(const std::string& pool) const;
    std::string pool_id(const std::string& chain, const std::string& lineage, const std::string& nonce,
                        const std::string& objective, const std::string& policy) const;
    bool split_ok() const;
    int64_t split_part(const std::string& name) const;
    bool leased(const std::string& pool, const std::string& work) const;
    bool earned(const std::string& pool, const std::string& work) const;
    int64_t earned_count() const;
    std::string worker(const std::string& pool, const std::string& work) const;
    std::string quote(const std::string& pool) const;
    int64_t balance(const std::string& pool) const;
    std::string reserve_pool(const std::string& outpoint) const;
    std::string reserve_role(const std::string& outpoint) const;
    int64_t reserve_atoms(const std::string& outpoint) const;
    int64_t sequence() const;
    int64_t l1_transactions() const;
    int64_t close_count() const;
    bool frozen() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool broadcast() const;
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;

private:
    SwarmPayPools m_pools;
    SwarmPaySplitBook m_split;
    SwarmPayObligations m_obligations;
    SwarmPayQuotes m_quotes;
    SwarmPayCollateral m_collateral;
    SwarmPayTransfer m_transfer;
    bool m_frozen{false};
    int64_t m_close_count{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYCYCLE_H
