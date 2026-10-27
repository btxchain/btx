// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/eligible.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationEligible::Apply(SwarmGenerationStrategy& strategy, bool license_allows, bool operator_grant, std::string& err) const
{
    // A download permission is not an operator training grant.
    // Eligibility starts false and is set only when both arguments are true.
    if (!license_allows || !operator_grant) {
        return SwarmGenerationFail(err, kSwarmGenerationLicense);
    }
    strategy.grant_eligible();
    return SwarmGenerationOk(err);
}

} // namespace modelnet
