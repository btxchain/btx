// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ECONOMYCLASS_H
#define BITCOIN_MODELNET_SWARM_ECONOMYCLASS_H

#include <modelnet/swarm_fourbook.h>
#include <modelnet/swarm_onechannel/swarm_onechannel.h>
#include <modelnet/swarm_paycycle/swarm_paycycle.h>
#include <modelnet/swarm_settlebuild/swarm_settlebuild.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** An economy name was empty. Nothing is stored. */
inline constexpr char SWARM_ECONOMYCLASS_ECONOMY[] = "ECONOMY";

/** The same channel was opened again. The first channel stays. */
inline constexpr char SWARM_ECONOMYCLASS_REPLAY[] = "REPLAY";

/**
 * Whole in-process economy class.
 * One channel binds many pools. Pay-cycle work stays HELD.
 * HTLC leaves are built and settlement stays unqualified.
 * The four balances are not merged. Nothing is broadcast.
 */
class SwarmEconomyClass {
public:
    bool Open(const std::string& channel, const std::string& pool_a, const std::string& pool_b, std::string& err);
    bool PayWork(const std::string& pool, const std::string& work, const std::string& worker, std::string& err);
    bool Quote(const std::string& pool, const std::string& usd, std::string& err);
    bool BuildLeaves(const std::vector<unsigned char>& payment_hash, const std::vector<unsigned char>& pubkey, int64_t timeout,
                     std::string& err);
    bool Settle(std::string& err);

    bool holds_money(const std::string& pool) const;
    int64_t earned_balance() const;
    bool qualified() const;
    bool network_opened() const;
    bool broadcast() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
    const std::vector<unsigned char>& claim_script() const;

private:
    std::string IdFor(const std::string& pool) const;

    SwarmPayCycle m_pay;
    SwarmOneChannel m_one;
    SwarmSettleBuild m_leaves;
    SwarmFourBook m_four;
    std::string m_channel;
    std::string m_pool_a;
    std::string m_pool_b;
    bool m_open{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ECONOMYCLASS_H
