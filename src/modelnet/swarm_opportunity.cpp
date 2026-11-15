// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_opportunity.h>

namespace modelnet {
namespace {

bool KnownActivity(const std::string& activity)
{
    static constexpr const char* kActivities[] = {
        "mine",
        "inference",
        "rollout",
        "train",
        "evaluate",
        "challenge",
        "simulate",
        "serve",
        "reproduce",
    };
    for (const char* name : kActivities) {
        if (activity == name) {
            return true;
        }
    }
    return false;
}

SwarmOpportunityResult Reject(const std::string& code, std::string& err)
{
    SwarmOpportunityResult result;
    result.comparable = false;
    result.spendable = false;
    result.compensation_atoms = 0;
    result.code = code;
    err = code;
    return result;
}

} // namespace

SwarmOpportunityResult SwarmCompareOpportunity(const SwarmOpportunityRequest& request, std::string& err)
{
    if (request.activity.empty() || !KnownActivity(request.activity)) {
        return Reject("OPPORTUNITY", err);
    }
    if (request.compensation_atoms <= 0) {
        return Reject("OPPORTUNITY", err);
    }
    if (!request.pool_funded) {
        // advertised_pool_atoms is not a funded balance and is not spent.
        return Reject("UNFUNDED", err);
    }
    if (!request.payment_enforceable) {
        return Reject("UNENFORCEABLE", err);
    }
    if (!request.meter_measured) {
        return Reject("METER_ABSENT", err);
    }
    SwarmOpportunityResult result;
    result.comparable = true;
    result.spendable = false;
    result.code = "COMPARABLE";
    err.clear();
    result.compensation_atoms = request.compensation_atoms;
    return result;
}

} // namespace modelnet
