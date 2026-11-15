// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_BOUNDARY_H
#define BTX_MODELNET_SWARM_BOUNDARY_H

#include <string>

namespace modelnet {

/** One authority. None of these covers a different kind. */
enum class SwarmCapability {
    TransportPin,
    RoleGrant,
    ResourcePolicy,
    DataGrant,
    EvaluationReport,
    PaymentMandate,
};

/**
 * True only when held and needed are the same kind. A different kind is
 * AUTHORITY. A transport pin is not a role, a resource policy, a data grant,
 * an evaluation, or a payment mandate.
 */
bool SwarmCapabilityCovers(SwarmCapability held, SwarmCapability needed, std::string& err);

/**
 * The accepted label is the realm policy label. A self-declared location does
 * not replace it. An empty policy label is TRUST_LABEL.
 */
bool SwarmTrustLabel(const std::string& policy_label, const std::string& self_declared, std::string& accepted, std::string& err);

struct SwarmRealmJoin {
    bool work_realm_joined{false};
    bool controller_committee_joined{false};
};

/**
 * Joining a work realm does not join the controller committee. Asking to join
 * both is COMMITTEE and leaves both flags false.
 */
bool SwarmJoinWorkRealm(SwarmRealmJoin& join, bool also_join_controller, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_BOUNDARY_H
