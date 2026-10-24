// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ECONOMY_H
#define BITCOIN_MODELNET_SWARM_ECONOMY_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmPoolCommit {
    std::string chain;
    std::string lineage;
    std::string nonce;
    std::string objective;
    std::string policy;
};

std::string SwarmPoolId(const SwarmPoolCommit& commit);

struct SwarmBalances {
    std::string confirmed_backing_atoms{"0"};
    std::string available_reward_budget_atoms{"0"};
    std::string immediately_payable_l2_atoms{"0"};
    std::string pending_or_earned_atoms{"0"};
    std::string status{"UNFUNDED"};
    bool holds_money{false};
};

struct SwarmFiatQuote {
    std::string usd;
    bool converted{false};
    std::string btx_atoms;
};

bool SwarmAcceptFiat(const SwarmFiatQuote& quote, std::string& atoms, std::string& err);

struct SwarmOpportunity {
    bool verified_backing{false};
    bool demonstrated_payment{false};
    bool signed_terms{false};
    int64_t reward_per_hour{0};
    int64_t accept_ppm{0};
    int64_t expense_per_hour{0};
    int64_t mining_alternative{0};
};

struct SwarmRank {
    bool ok{false};
    std::string code;
    int64_t advantage{0};
};

SwarmRank SwarmRankOpportunity(const SwarmOpportunity& offer);

class SwarmLedger {
public:
    std::string CreatePool(const SwarmPoolCommit& commit, std::string& err);
    bool ObserveBacking(const std::string& pool, const std::string& outpoint, int64_t amount, int64_t fee_reserve,
                        const std::string& script, int64_t now_ms, std::string& err);
    bool PledgeChannel(const std::string& pool, const std::string& outpoint, std::string& err);
    bool FundChannel(const std::string& pool, const std::string& outpoint, bool refund_signed, std::string& err);
    bool Invalidate(const std::string& outpoint, const std::string& reason, std::string& err);
    std::string GrantMandate(const std::string& pool, const std::string& actor, int64_t amount, int64_t expires_ms,
                             const std::vector<std::string>& recipients, const std::string& nonce, std::string& err);
    bool Reserve(const std::string& mandate, const std::string& actor, const std::string& work, const std::string& worker,
                 int64_t amount, const std::string& terms, bool accept_unsecured, std::string& reservation, std::string& err);
    bool AcceptWork(const std::string& reservation, const std::string& receipt, std::string& err);
    bool Cancel(const std::string& reservation, std::string& err);
    SwarmBalances Balances(const std::string& pool) const;
    bool Conserved(const std::string& pool) const;
    bool EarnedSurvives(const std::string& pool, const std::string& reservation) const;

private:
    struct Backing {
        std::string pool;
        std::string outpoint;
        int64_t amount{0};
        int64_t fee_reserve{0};
        std::string script;
        std::string state{"OBSERVED_UNSPENT"};
        bool channel_collateral{false};
        bool channel_funded{false};
    };
    struct Mandate {
        std::string id;
        std::string pool;
        std::string actor;
        int64_t amount{0};
        int64_t used{0};
        int64_t expires_ms{0};
        std::vector<std::string> recipients;
        bool revoked{false};
    };
    struct Obligation {
        std::string id;
        std::string pool;
        std::string work;
        std::string worker;
        std::string mandate;
        std::string receipt;
        std::string terms;
        std::string state;
        int64_t amount{0};
    };
    std::map<std::string, std::string> m_status;
    std::map<std::string, Backing> m_backing;
    std::map<std::string, Mandate> m_mandates;
    std::map<std::string, Obligation> m_obligations;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ECONOMY_H
