// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_payreg/swarm_payreg.h>

#include <pqkey.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmPayReg::KnownPool(const std::string& pool) const
{
    return m_open && (pool == m_pool_a || pool == m_pool_b);
}

bool SwarmPayReg::Open(const std::string& channel, const std::string& pool_a, const std::string& pool_b, std::string& err)
{
    if (m_open && channel != m_channel) {
        std::string inner;
        (void)m_economy.Open(channel, pool_a, pool_b, inner);
        err = kSwarmPayRegNotOpened;
        return false;
    }
    if (!m_economy.Open(channel, pool_a, pool_b, err)) {
        return false;
    }
    m_channel = channel;
    m_pool_a = pool_a;
    m_pool_b = pool_b;
    m_open = true;
    err.clear();
    return true;
}

bool SwarmPayReg::Reserve(const std::string& pool, const std::string& outpoint, int64_t atoms, std::string& err)
{
    if (atoms < 1) {
        err = kSwarmPayRegAmount;
        return false;
    }
    if (outpoint.empty()) {
        err = kSwarmPayRegOutpoint;
        return false;
    }
    if (!m_open) {
        err = kSwarmPayRegNotOpened;
        return false;
    }
    if (!KnownPool(pool)) {
        err = kSwarmPayRegPool;
        return false;
    }

    const auto existing = m_collateral.find(outpoint);
    if (existing != m_collateral.end()) {
        // One outpoint funds one pool. The other pool does not inherit it.
        if (existing->second.pool != pool) {
            err = kSwarmPayRegOutpoint;
            return false;
        }
        err = kSwarmPayRegReplay;
        return false;
    }

    Collateral row;
    row.pool = pool;
    row.atoms = atoms;
    m_collateral.emplace(outpoint, std::move(row));
    m_funded[pool] += atoms;
    err.clear();
    return true;
}

bool SwarmPayReg::Terms(const std::string& route_id, int64_t atoms, int64_t timeout, std::string& err)
{
    if (route_id.empty()) {
        err = kSwarmPayRegTerms;
        return false;
    }
    if (atoms < 1) {
        err = kSwarmPayRegAmount;
        return false;
    }
    if (timeout < 1) {
        err = kSwarmPayRegTimeout;
        return false;
    }
    if (!m_open) {
        err = kSwarmPayRegNotOpened;
        return false;
    }

    const auto existing = m_terms.find(route_id);
    if (existing != m_terms.end()) {
        if (existing->second.atoms != atoms || existing->second.timeout != timeout) {
            err = kSwarmPayRegTerms;
            return false;
        }
        err.clear();
        return true;
    }

    TermsRecord record;
    record.atoms = atoms;
    record.timeout = timeout;
    m_terms.emplace(route_id, record);
    err.clear();
    return true;
}

bool SwarmPayReg::Claim(const std::string& work_id, std::string& err)
{
    if (work_id.empty()) {
        err = kSwarmPayRegClaim;
        return false;
    }
    m_claims.insert(work_id);
    err.clear();
    return true;
}

void SwarmPayReg::FailCompute()
{
    m_compute_failed = true;
}

bool SwarmPayReg::Build(const std::vector<unsigned char>& payment_hash, const std::vector<unsigned char>& pubkey,
                        int64_t timeout, std::string& err)
{
    if (payment_hash.size() != kSwarmPayRegHashSize) {
        err = kSwarmPayRegPreimage;
        return false;
    }
    if (pubkey.size() != MLDSA44_PUBKEY_SIZE) {
        err = kSwarmPayRegKey;
        return false;
    }
    if (timeout != kSwarmPayRegRefundTimeout) {
        err = kSwarmPayRegTimeout;
        return false;
    }
    if (!m_settle.BuildClaim(payment_hash, pubkey, err)) {
        return false;
    }
    return m_settle.BuildRefund(timeout, pubkey, err);
}

bool SwarmPayReg::Settle(std::string& err)
{
    std::string inner;
    (void)m_settle.Settle(inner);
    err = kSwarmPayRegUnqualified;
    return false;
}

bool SwarmPayReg::Credit(const std::string& pool, int64_t atoms, std::string& err)
{
    if (atoms < 1) {
        err = kSwarmPayRegAmount;
        return false;
    }
    if (pool.empty()) {
        err = kSwarmPayRegPool;
        return false;
    }
    if (!m_open) {
        err = kSwarmPayRegNotOpened;
        return false;
    }
    if (!KnownPool(pool)) {
        err = kSwarmPayRegPool;
        return false;
    }
    // The note is recorded. It is not added to the funded collateral balance.
    m_credit[pool] += atoms;
    err = kSwarmPayRegNotBacking;
    return false;
}

bool SwarmPayReg::claim_kept(const std::string& work_id) const
{
    return m_claims.find(work_id) != m_claims.end();
}

bool SwarmPayReg::compute_failed() const
{
    return m_compute_failed;
}

std::string SwarmPayReg::reserve_pool(const std::string& outpoint) const
{
    const auto it = m_collateral.find(outpoint);
    if (it == m_collateral.end()) {
        return {};
    }
    return it->second.pool;
}

int64_t SwarmPayReg::reserve_atoms(const std::string& outpoint) const
{
    const auto it = m_collateral.find(outpoint);
    if (it == m_collateral.end()) {
        return 0;
    }
    return it->second.atoms;
}

int64_t SwarmPayReg::funded_balance(const std::string& pool) const
{
    const auto it = m_funded.find(pool);
    if (it == m_funded.end()) {
        return 0;
    }
    return it->second;
}

int64_t SwarmPayReg::credit_note(const std::string& pool) const
{
    const auto it = m_credit.find(pool);
    if (it == m_credit.end()) {
        return 0;
    }
    return it->second;
}

bool SwarmPayReg::terms_stored(const std::string& route_id) const
{
    return m_terms.find(route_id) != m_terms.end();
}

int64_t SwarmPayReg::terms_atoms(const std::string& route_id) const
{
    const auto it = m_terms.find(route_id);
    if (it == m_terms.end()) {
        return 0;
    }
    return it->second.atoms;
}

int64_t SwarmPayReg::terms_timeout(const std::string& route_id) const
{
    const auto it = m_terms.find(route_id);
    if (it == m_terms.end()) {
        return 0;
    }
    return it->second.timeout;
}

bool SwarmPayReg::holds_money(const std::string& pool) const
{
    return m_economy.holds_money(pool);
}

const std::vector<unsigned char>& SwarmPayReg::claim_script() const
{
    return m_settle.claim_script();
}

const std::vector<unsigned char>& SwarmPayReg::refund_script() const
{
    return m_settle.refund_script();
}

std::string SwarmPayReg::Mode() const
{
    return std::string{kSwarmPayRegMode};
}

bool SwarmPayReg::qualified() const
{
    return kSwarmPayRegQualified;
}

bool SwarmPayReg::broadcast() const
{
    return kSwarmPayRegBroadcast;
}

bool SwarmPayReg::launched() const
{
    return kSwarmPayRegLaunched;
}

bool SwarmPayReg::gpu() const
{
    return kSwarmPayRegGpu;
}

bool SwarmPayReg::spendable() const
{
    return kSwarmPayRegSpendable;
}

bool SwarmPayReg::mainnet() const
{
    return kSwarmPayRegMainnet;
}

int64_t SwarmPayReg::atoms_moved() const
{
    return kSwarmPayRegAtomsMoved;
}

std::string SwarmPayReg::automatic_spend() const
{
    return std::string{kSwarmPayRegAutomaticSpend};
}

} // namespace modelnet
