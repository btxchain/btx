// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_OPPORTUNITY_H
#define BTX_MODELNET_SWARM_OPPORTUNITY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A request to compare one activity's compensation. Amounts are BTX atoms.
 * advertised_pool_atoms is an advertisement, not a funded balance. This
 * request does not broadcast and does not carry a spend key.
 */
struct SwarmOpportunityRequest {
    std::string activity;
    int64_t advertised_pool_atoms{0};
    bool pool_funded{false};
    bool payment_enforceable{false};
    bool meter_measured{false};
    int64_t compensation_atoms{0};
};

/**
 * A comparison answer. spendable stays false: this function does not
 * broadcast and does not use a spend key. compensation_atoms stays 0
 * unless the opportunity is comparable. Currency is BTX atoms.
 */
struct SwarmOpportunityResult {
    bool comparable{false};
    bool spendable{false};
    int64_t compensation_atoms{0};
    std::string code;
};

/**
 * Compares one opportunity. Nothing is broadcast and no spend key is used.
 * Currency is BTX atoms.
 *
 * Order: an empty or unknown activity is OPPORTUNITY. Known activities are
 * mine, inference, rollout, train, evaluate, challenge, simulate, serve,
 * and reproduce. compensation_atoms <= 0 is OPPORTUNITY. pool_funded false
 * is UNFUNDED even when advertised_pool_atoms is large. payment_enforceable
 * false is UNENFORCEABLE. meter_measured false is METER_ABSENT. Those
 * results are not comparable and compensation_atoms stays 0. Otherwise the
 * result is COMPARABLE, err is cleared, spendable stays false, and
 * compensation_atoms is copied from the request.
 */
SwarmOpportunityResult SwarmCompareOpportunity(const SwarmOpportunityRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_OPPORTUNITY_H
