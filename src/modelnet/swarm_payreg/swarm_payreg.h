// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYREG_H
#define BITCOIN_MODELNET_SWARM_PAYREG_H

#include <modelnet/swarm_economyclass/swarm_economyclass.h>
#include <modelnet/swarm_payreg/codes.h>
#include <modelnet/swarm_payreg/limits.h>
#include <modelnet/swarm_settlebuild/swarm_settlebuild.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process payment register.
 *
 * ASR-PAY-001..004 and DS-PAY-001..006 are enforced here only as far as
 * one process can enforce them. This object does not broadcast, spawn a
 * process, open a socket, or select mainnet. Mode() is REGTEST_UNBROADCAST.
 * spendable() stays false. Collateral is not advertised as spendable money.
 *
 * Open calls SwarmEconomyClass::Open. A second channel id is NOT_OPENED
 * and leaves the first channel and its pools in place.
 *
 * Reserve records collateral for one opened pool. atoms below 1 is AMOUNT
 * and stores nothing. An empty outpoint is OUTPOINT and stores nothing.
 * The same outpoint cannot fund two pools: the second call is OUTPOINT and
 * stores nothing. Collateral recorded for one pool is not collateral for
 * the other. The same outpoint on the same pool is REPLAY and does not add
 * atoms. holds_money() follows the economy class, so only the pool that
 * class funded reports true.
 *
 * Terms stores the first atoms and timeout for a route id. A later call
 * with that route id and different atoms or timeout is TERMS and does not
 * change the stored terms.
 *
 * Claim records an earned claim and returns true. FailCompute sets
 * compute_failed() true and does not erase the claim. claim_kept(work_id)
 * stays true.
 *
 * Build calls SwarmSettleBuild::BuildClaim and BuildRefund when the
 * payment hash is 32 bytes, the pubkey is the ML-DSA-44 size, and the
 * timeout is 160. Settle calls SwarmSettleBuild::Settle and returns false
 * with UNQUALIFIED. qualified() stays false. broadcast() stays false.
 * atoms_moved() stays 0. automatic_spend() stays "0".
 *
 * Credit stores a credit note and returns false with NOT_BACKING. The note
 * does not increase funded_balance().
 *
 * launched() and gpu() stay false.
 */
class SwarmPayReg {
public:
    bool Open(const std::string& channel, const std::string& pool_a, const std::string& pool_b, std::string& err);
    bool Reserve(const std::string& pool, const std::string& outpoint, int64_t atoms, std::string& err);
    bool Terms(const std::string& route_id, int64_t atoms, int64_t timeout, std::string& err);
    bool Claim(const std::string& work_id, std::string& err);
    void FailCompute();
    bool Build(const std::vector<unsigned char>& payment_hash, const std::vector<unsigned char>& pubkey, int64_t timeout,
               std::string& err);
    bool Settle(std::string& err);
    bool Credit(const std::string& pool, int64_t atoms, std::string& err);

    bool claim_kept(const std::string& work_id) const;
    bool compute_failed() const;
    std::string reserve_pool(const std::string& outpoint) const;
    int64_t reserve_atoms(const std::string& outpoint) const;
    int64_t funded_balance(const std::string& pool) const;
    int64_t credit_note(const std::string& pool) const;
    bool terms_stored(const std::string& route_id) const;
    int64_t terms_atoms(const std::string& route_id) const;
    int64_t terms_timeout(const std::string& route_id) const;
    bool holds_money(const std::string& pool) const;
    const std::vector<unsigned char>& claim_script() const;
    const std::vector<unsigned char>& refund_script() const;

    std::string Mode() const;
    bool qualified() const;
    bool broadcast() const;
    bool launched() const;
    bool gpu() const;
    bool spendable() const;
    bool mainnet() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;

private:
    bool KnownPool(const std::string& pool) const;

    struct Collateral {
        std::string pool;
        int64_t atoms{0};
    };

    struct TermsRecord {
        int64_t atoms{0};
        int64_t timeout{0};
    };

    SwarmEconomyClass m_economy;
    SwarmSettleBuild m_settle;
    std::string m_channel;
    std::string m_pool_a;
    std::string m_pool_b;
    bool m_open{false};
    bool m_compute_failed{false};
    std::map<std::string, Collateral> m_collateral;
    std::map<std::string, int64_t> m_funded;
    std::map<std::string, int64_t> m_credit;
    std::map<std::string, TermsRecord> m_terms;
    std::set<std::string> m_claims;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYREG_H
