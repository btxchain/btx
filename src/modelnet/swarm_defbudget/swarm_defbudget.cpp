// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_defbudget/swarm_defbudget.h>

#include <limits>
#include <map>
#include <string>
#include <utility>

namespace modelnet {
namespace {

bool KnownPool(const std::string& pool)
{
    return pool == kSwarmDefBudgetPoolReadiness || pool == kSwarmDefBudgetPoolIncident ||
           pool == kSwarmDefBudgetPoolImprovement;
}

} // namespace

SwarmDefBudget::SwarmDefBudget()
{
    m_pools.emplace(kSwarmDefBudgetPoolReadiness, PoolBook{});
    m_pools.emplace(kSwarmDefBudgetPoolIncident, PoolBook{});
    m_pools.emplace(kSwarmDefBudgetPoolImprovement, PoolBook{});
}

bool SwarmDefBudget::Fund(const std::string& pool, const std::string& outpoint, int64_t atoms, std::string& err)
{
    auto it = m_pools.find(pool);
    if (!KnownPool(pool) || it == m_pools.end()) {
        err = kSwarmDefBudgetPool;
        return false;
    }
    if (atoms < 1) {
        err = kSwarmDefBudgetAmount;
        return false;
    }
    if (outpoint.empty()) {
        err = kSwarmDefBudgetOutpoint;
        return false;
    }
    if (m_outpoints.find(outpoint) != m_outpoints.end()) {
        err = kSwarmDefBudgetOutpoint;
        return false;
    }
    if (it->second.balance > std::numeric_limits<int64_t>::max() - atoms) {
        err = kSwarmDefBudgetAmount;
        return false;
    }

    if (!it->second.funded) {
        it->second.outpoint = outpoint;
        it->second.funded = true;
    }
    it->second.balance += atoms;
    m_outpoints.emplace(outpoint, pool);
    err.clear();
    return true;
}

bool SwarmDefBudget::Join(const std::string& pool, const std::string& member, std::string& err)
{
    auto it = m_pools.find(pool);
    if (!KnownPool(pool) || it == m_pools.end()) {
        err = kSwarmDefBudgetPool;
        return false;
    }
    if (member.empty()) {
        err = kSwarmDefBudgetMember;
        return false;
    }
    it->second.members.insert(member);
    err = kSwarmDefBudgetNotPaid;
    return false;
}

bool SwarmDefBudget::Earn(const std::string& pool, const std::string& work_id, const std::string& member, int64_t atoms,
                          std::string& err)
{
    return EarnWork(pool, work_id, nullptr, member, atoms, err);
}

bool SwarmDefBudget::Earn(const std::string& pool, const std::string& work_id, const std::string& receipt,
                          const std::string& member, int64_t atoms, std::string& err)
{
    return EarnWork(pool, work_id, &receipt, member, atoms, err);
}

bool SwarmDefBudget::EarnWork(const std::string& pool, const std::string& work_id, const std::string* receipt,
                              const std::string& member, int64_t atoms, std::string& err)
{
    auto it = m_pools.find(pool);
    if (!KnownPool(pool) || it == m_pools.end()) {
        err = kSwarmDefBudgetPool;
        return false;
    }
    if (atoms < 1) {
        err = kSwarmDefBudgetAmount;
        return false;
    }
    if (work_id.empty()) {
        err = kSwarmDefBudgetWork;
        return false;
    }
    if (receipt != nullptr && receipt->empty()) {
        err = kSwarmDefBudgetReceipt;
        return false;
    }
    if (member.empty()) {
        err = kSwarmDefBudgetMember;
        return false;
    }
    if (!it->second.funded) {
        err = kSwarmDefBudgetFunding;
        return false;
    }
    if (m_earned.find(work_id) != m_earned.end()) {
        err = kSwarmDefBudgetReplay;
        return false;
    }
    if (receipt != nullptr && m_receipts.find(*receipt) != m_receipts.end()) {
        err = kSwarmDefBudgetDuplicate;
        return false;
    }
    if (it->second.earned > std::numeric_limits<int64_t>::max() - atoms) {
        err = kSwarmDefBudgetAmount;
        return false;
    }

    EarnedRow row;
    row.pool = pool;
    row.member = member;
    row.atoms = atoms;
    if (receipt != nullptr) {
        row.receipt = *receipt;
        m_receipts.emplace(*receipt, work_id);
    }
    m_earned.emplace(work_id, std::move(row));
    it->second.earned += atoms;
    err.clear();
    return true;
}

bool SwarmDefBudget::Milestone(const std::string& pool, const std::string& work_id, int64_t requested, int64_t cap,
                               std::string& err)
{
    auto it = m_pools.find(pool);
    if (!KnownPool(pool) || it == m_pools.end()) {
        err = kSwarmDefBudgetPool;
        return false;
    }
    if (work_id.empty()) {
        err = kSwarmDefBudgetWork;
        return false;
    }
    if (requested < 1) {
        err = kSwarmDefBudgetAmount;
        return false;
    }
    if (requested > cap) {
        err = kSwarmDefBudgetCap;
        return false;
    }
    if (!it->second.funded) {
        err = kSwarmDefBudgetFunding;
        return false;
    }
    if (m_milestones.find(work_id) != m_milestones.end()) {
        err = kSwarmDefBudgetReplay;
        return false;
    }

    const int64_t paid = requested < cap ? requested : cap;
    if (paid > it->second.balance) {
        err = kSwarmDefBudgetNegative;
        return false;
    }

    MilestoneRow row;
    row.pool = pool;
    row.requested = requested;
    row.cap = cap;
    row.paid = paid;
    m_milestones.emplace(work_id, row);
    it->second.balance -= paid;
    err.clear();
    return true;
}

bool SwarmDefBudget::SetPayer(const std::string& payer, std::string& err)
{
    if (payer.empty()) {
        err = kSwarmDefBudgetPayer;
        return false;
    }
    if (!m_payer.empty()) {
        err = kSwarmDefBudgetReplay;
        return false;
    }
    m_payer = payer;
    err.clear();
    return true;
}

bool SwarmDefBudget::SelfDeal(const std::string& member, std::string& err)
{
    if (member.empty()) {
        err = kSwarmDefBudgetMember;
        return false;
    }
    if (m_payer.empty()) {
        err = kSwarmDefBudgetPayer;
        return false;
    }
    if (member == m_payer) {
        err = kSwarmDefBudgetSelf;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmDefBudget::holds_money(const std::string& pool) const
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end()) {
        return false;
    }
    return it->second.funded;
}

int64_t SwarmDefBudget::balance(const std::string& pool) const
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end()) {
        return 0;
    }
    return it->second.balance;
}

bool SwarmDefBudget::member_of(const std::string& pool, const std::string& member) const
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end()) {
        return false;
    }
    return it->second.members.find(member) != it->second.members.end();
}

bool SwarmDefBudget::earned(const std::string& work_id) const
{
    return m_earned.find(work_id) != m_earned.end();
}

int64_t SwarmDefBudget::earned_atoms(const std::string& pool) const
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end()) {
        return 0;
    }
    return it->second.earned;
}

int64_t SwarmDefBudget::earned_count() const
{
    return static_cast<int64_t>(m_earned.size());
}

bool SwarmDefBudget::milestone_stored(const std::string& work_id) const
{
    return m_milestones.find(work_id) != m_milestones.end();
}

int64_t SwarmDefBudget::milestone_paid(const std::string& work_id) const
{
    const auto it = m_milestones.find(work_id);
    if (it == m_milestones.end()) {
        return 0;
    }
    return it->second.paid;
}

const std::string& SwarmDefBudget::outpoint(const std::string& pool) const
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end()) {
        static const std::string empty;
        return empty;
    }
    return it->second.outpoint;
}

const std::string& SwarmDefBudget::payer() const
{
    return m_payer;
}

int64_t SwarmDefBudget::atoms_moved() const
{
    return kSwarmDefBudgetAtomsMoved;
}

bool SwarmDefBudget::broadcast() const
{
    return kSwarmDefBudgetBroadcast;
}

bool SwarmDefBudget::launched() const
{
    return kSwarmDefBudgetLaunched;
}

bool SwarmDefBudget::gpu() const
{
    return kSwarmDefBudgetGpu;
}

std::string SwarmDefBudget::automatic_spend() const
{
    return std::string{kSwarmDefBudgetAutomaticSpend};
}

} // namespace modelnet
