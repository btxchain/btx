// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/swarm_paycycle.h>

#include <modelnet/swarm_paycycle/codes.h>
#include <modelnet/swarm_paycycle/identity.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmPayCycle::Publish(const std::string& chain, const std::string& lineage, const std::string& nonce,
                            const std::string& objective, const std::string& policy, std::string& err)
{
    return m_pools.Publish(chain, lineage, nonce, objective, policy, err);
}

bool SwarmPayCycle::RaiseEpoch(const std::string& pool, const std::string& new_policy, std::string& err)
{
    return m_pools.RaiseEpoch(pool, new_policy, err);
}

bool SwarmPayCycle::Split(int64_t rollout, int64_t negative, int64_t reproduction, int64_t evaluation,
                          int64_t challengers, int64_t milestone, std::string& err)
{
    return m_split.Store(rollout, negative, reproduction, evaluation, challengers, milestone, err);
}

bool SwarmPayCycle::Fund(const std::string& pool, bool refund_bound, std::string& err)
{
    return m_pools.Fund(pool, refund_bound, err);
}

bool SwarmPayCycle::Lease(const std::string& pool, const std::string& work, const std::string& worker, std::string& err)
{
    if (!m_pools.funded(pool)) {
        err = SWARM_PAYCYCLE_FUNDING;
        return false;
    }
    return m_obligations.Lease(pool, work, worker, err);
}

bool SwarmPayCycle::Pay(const std::string& pool, const std::string& work, const std::string& label, std::string& err)
{
    return m_obligations.Pay(pool, work, label, err);
}

bool SwarmPayCycle::Quote(const std::string& pool, const std::string& usd, std::string& err)
{
    return m_quotes.Store(pool, usd, err);
}

bool SwarmPayCycle::Reserve(const std::string& pool, const std::string& outpoint, int64_t atoms, std::string& err,
                            const std::string& role)
{
    if (m_frozen) {
        err = SWARM_PAYCYCLE_FROZEN;
        return false;
    }
    return m_collateral.Reserve(m_pools, pool, outpoint, atoms, role, err);
}

bool SwarmPayCycle::ApplyBatch(const std::string& from_pool, const std::string& to_pool, const std::string& payment_id,
                               int64_t atoms, std::string& err)
{
    if (m_frozen) {
        err = SWARM_PAYCYCLE_FROZEN;
        return false;
    }
    // A committed batch is an in-memory balance move. It builds no L1 transaction.
    return m_transfer.Apply(m_pools, from_pool, to_pool, payment_id, atoms, err);
}

int64_t SwarmPayCycle::CloseTemplate()
{
    // One count of funded pools that still have a positive balance.
    // Payments are not expanded into close entries.
    m_close_count = m_pools.PositiveFunded();
    return m_close_count;
}

bool SwarmPayCycle::Freeze(std::string& err)
{
    m_frozen = true;
    err = SWARM_PAYCYCLE_FREEZE;
    return false;
}

int64_t SwarmPayCycle::pool_count() const
{
    return m_pools.count();
}

bool SwarmPayCycle::funded(const std::string& pool) const
{
    return m_pools.funded(pool);
}

bool SwarmPayCycle::holds_money() const
{
    return m_pools.holds_money();
}

bool SwarmPayCycle::holds_money(const std::string& pool) const
{
    return m_pools.holds_money(pool);
}

std::string SwarmPayCycle::pool_id(const std::string& chain, const std::string& lineage, const std::string& nonce,
                                   const std::string& objective, const std::string& policy) const
{
    return SwarmPayCyclePoolId(chain, lineage, nonce, objective, policy);
}

bool SwarmPayCycle::split_ok() const
{
    return m_split.ok();
}

int64_t SwarmPayCycle::split_part(const std::string& name) const
{
    return m_split.part(name);
}

bool SwarmPayCycle::leased(const std::string& pool, const std::string& work) const
{
    return m_obligations.leased(pool, work);
}

bool SwarmPayCycle::earned(const std::string& pool, const std::string& work) const
{
    return m_obligations.earned(pool, work);
}

int64_t SwarmPayCycle::earned_count() const
{
    return m_obligations.earned_count();
}

std::string SwarmPayCycle::worker(const std::string& pool, const std::string& work) const
{
    return m_obligations.worker(pool, work);
}

std::string SwarmPayCycle::quote(const std::string& pool) const
{
    return m_quotes.get(pool);
}

int64_t SwarmPayCycle::balance(const std::string& pool) const
{
    return m_pools.balance(pool);
}

std::string SwarmPayCycle::reserve_pool(const std::string& outpoint) const
{
    return m_collateral.pool(outpoint);
}

std::string SwarmPayCycle::reserve_role(const std::string& outpoint) const
{
    return m_collateral.role(outpoint);
}

int64_t SwarmPayCycle::reserve_atoms(const std::string& outpoint) const
{
    return m_collateral.atoms(outpoint);
}

int64_t SwarmPayCycle::sequence() const
{
    return m_transfer.sequence();
}

int64_t SwarmPayCycle::l1_transactions() const
{
    return 0;
}

int64_t SwarmPayCycle::close_count() const
{
    return m_close_count;
}

bool SwarmPayCycle::frozen() const
{
    return m_frozen;
}

int64_t SwarmPayCycle::atoms_moved() const
{
    return 0;
}

std::string SwarmPayCycle::automatic_spend() const
{
    return "0";
}

bool SwarmPayCycle::broadcast() const
{
    return false;
}

bool SwarmPayCycle::launched() const
{
    return false;
}

bool SwarmPayCycle::gpu() const
{
    return false;
}

int64_t SwarmPayCycle::bytes_moved() const
{
    return 0;
}

} // namespace modelnet
