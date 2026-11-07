// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEFBUDGET_H
#define BITCOIN_MODELNET_SWARM_DEFBUDGET_H

#include <modelnet/swarm_defbudget/codes.h>
#include <modelnet/swarm_defbudget/limits.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace modelnet {

/**
 * In-memory defense budget for three pools.
 *
 * The pools are readiness, incident, and improvement. Any other name is
 * POOL and stores nothing. Each pool has its own funded balance and its
 * own earned total. Funding one pool leaves the others unchanged.
 * holds_money(pool) is true only after a successful Fund of that pool,
 * and it stays true after a later milestone lowers the balance.
 *
 * Fund(pool, outpoint, atoms, err) adds atoms from one outpoint.
 * atoms below 1 is AMOUNT. An empty outpoint is OUTPOINT. An outpoint
 * that already funded any pool, including this one, is OUTPOINT and
 * stores nothing for this call. A new outpoint adds its atoms to that
 * pool only. A sum that would pass int64 max is AMOUNT and stores nothing.
 * Checks run in that order.
 *
 * Join(pool, member, err) records membership and returns false with
 * NOT_PAID. An empty member is MEMBER and stores nothing. Join writes
 * no earned row and does not fund the pool.
 *
 * Earn(pool, work_id, member, atoms, err) stores an earned row.
 * Earn(pool, work_id, receipt, member, atoms, err) does the same and
 * also records the receipt text. atoms below 1 is AMOUNT. An unknown
 * pool is POOL. An empty work id is WORK. An empty receipt on the
 * receipt overload is RECEIPT. An empty member is MEMBER. An unfunded
 * pool is FUNDING. The same work id again, on any pool, is REPLAY.
 * A different work id that reuses receipt text already stored on any
 * pool is DUPLICATE and stores nothing. Checks run in that order.
 * Earn adds to the earned total and leaves the funded balance as it is.
 *
 * Milestone(pool, work_id, requested, cap, err) pays that pool's funded
 * balance. An empty work id is WORK. requested below 1 is AMOUNT.
 * requested above cap is CAP and pays nothing. An unfunded pool is
 * FUNDING. The same work id again is REPLAY. Otherwise the paid amount
 * is min(requested, cap). requested equal to cap takes that path and is
 * stored when the balance covers it. A payout above the balance is
 * NEGATIVE and stores nothing, so the balance stays non-negative.
 * A stored milestone lowers only that pool's balance. atoms_moved()
 * stays 0.
 *
 * SetPayer records one payer. An empty payer is PAYER. A later SetPayer
 * is REPLAY and keeps the first payer. SelfDeal(member, err) returns
 * false with SELF when the member is that payer, and stores no earned
 * row. A different member returns true and still stores no earned row.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend()
 * returns "0". atoms_moved() returns 0. This class does not broadcast
 * and does not spend.
 */
class SwarmDefBudget {
public:
    SwarmDefBudget();

    bool Fund(const std::string& pool, const std::string& outpoint, int64_t atoms, std::string& err);
    bool Join(const std::string& pool, const std::string& member, std::string& err);
    bool Earn(const std::string& pool, const std::string& work_id, const std::string& member, int64_t atoms,
              std::string& err);
    bool Earn(const std::string& pool, const std::string& work_id, const std::string& receipt, const std::string& member,
              int64_t atoms, std::string& err);
    bool Milestone(const std::string& pool, const std::string& work_id, int64_t requested, int64_t cap, std::string& err);
    bool SetPayer(const std::string& payer, std::string& err);
    bool SelfDeal(const std::string& member, std::string& err);

    bool holds_money(const std::string& pool) const;
    int64_t balance(const std::string& pool) const;
    bool member_of(const std::string& pool, const std::string& member) const;
    bool earned(const std::string& work_id) const;
    int64_t earned_atoms(const std::string& pool) const;
    int64_t earned_count() const;
    bool milestone_stored(const std::string& work_id) const;
    int64_t milestone_paid(const std::string& work_id) const;
    const std::string& outpoint(const std::string& pool) const;
    const std::string& payer() const;

    int64_t atoms_moved() const;
    bool broadcast() const;
    bool launched() const;
    bool gpu() const;
    std::string automatic_spend() const;

private:
    struct PoolBook {
        int64_t balance{0};
        int64_t earned{0};
        std::string outpoint;
        bool funded{false};
        std::set<std::string> members;
    };

    struct EarnedRow {
        std::string pool;
        std::string member;
        std::string receipt;
        int64_t atoms{0};
    };

    struct MilestoneRow {
        std::string pool;
        int64_t requested{0};
        int64_t cap{0};
        int64_t paid{0};
    };

    bool EarnWork(const std::string& pool, const std::string& work_id, const std::string* receipt,
                  const std::string& member, int64_t atoms, std::string& err);

    std::map<std::string, PoolBook> m_pools;
    std::map<std::string, std::string> m_outpoints;
    std::map<std::string, EarnedRow> m_earned;
    std::map<std::string, std::string> m_receipts;
    std::map<std::string, MilestoneRow> m_milestones;
    std::string m_payer;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEFBUDGET_H
