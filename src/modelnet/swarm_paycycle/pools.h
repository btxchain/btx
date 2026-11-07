// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYCYCLE_POOLS_H
#define BITCOIN_MODELNET_SWARM_PAYCYCLE_POOLS_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Many pools on one mesh. A pool starts unfunded with balance 0.
 * Fund marks the refund-bound flag and does not assign a balance.
 * Raising the policy stores a new id and leaves the old pool in place.
 */
class SwarmPayPools {
public:
    bool Publish(const std::string& chain, const std::string& lineage, const std::string& nonce,
                 const std::string& objective, const std::string& policy, std::string& err);
    bool RaiseEpoch(const std::string& pool, const std::string& new_policy, std::string& err);
    bool Fund(const std::string& pool, bool refund_bound, std::string& err);

    int64_t count() const;
    bool known(const std::string& pool) const;
    bool funded(const std::string& pool) const;
    bool holds_money() const;
    bool holds_money(const std::string& pool) const;
    int64_t balance(const std::string& pool) const;
    int64_t PositiveFunded() const;

    /** Add channel-collateral atoms. False leaves the balance unchanged. */
    bool Credit(const std::string& pool, int64_t atoms);

    /**
     * Move atoms from one in-memory balance to another.
     * Both pools must be funded. atoms below 1 is AMOUNT.
     * A short balance is NEGATIVE and commits nothing.
     * The same pool with enough balance is a net-zero move.
     */
    bool Move(const std::string& from_pool, const std::string& to_pool, int64_t atoms, std::string& err);

private:
    struct Pool {
        std::string chain;
        std::string lineage;
        std::string nonce;
        std::string objective;
        std::string policy;
        bool funded{false};
        int64_t balance{0};
    };

    std::map<std::string, Pool> m_pools;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYCYCLE_POOLS_H
