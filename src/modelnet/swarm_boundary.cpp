// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_boundary.h>

namespace modelnet {

bool SwarmCapabilityCovers(SwarmCapability held, SwarmCapability needed, std::string& err)
{
    if (held != needed) {
        err = "AUTHORITY";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmTrustLabel(const std::string& policy_label, const std::string& self_declared, std::string& accepted, std::string& err)
{
    (void)self_declared;
    if (policy_label.empty()) {
        accepted.clear();
        err = "TRUST_LABEL";
        return false;
    }
    accepted = policy_label;
    err.clear();
    return true;
}

bool SwarmJoinWorkRealm(SwarmRealmJoin& join, bool also_join_controller, std::string& err)
{
    if (also_join_controller) {
        join.work_realm_joined = false;
        join.controller_committee_joined = false;
        err = "COMMITTEE";
        return false;
    }
    join.work_realm_joined = true;
    join.controller_committee_joined = false;
    err.clear();
    return true;
}

} // namespace modelnet
