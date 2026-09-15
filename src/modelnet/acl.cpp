// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acl.h>

#include <modelnet/types.h>

namespace modelnet {

bool ModelAcl::Denied(PolicyDim dim, const std::string& subject) const
{
    // AUTO_PAY / AUTO_SEED / TRUST_METADATA are off unless the operator set the
    // matching flag. A denylist subject is still denied on every other dim.
    if (dim == PolicyDim::AUTO_PAY && !auto_pay) return true;
    if (dim == PolicyDim::AUTO_SEED && !auto_seed) return true;
    if (dim == PolicyDim::TRUST_METADATA && !trust_metadata) return true;
    if (deny_endpoint.count(subject) || deny_subnet.count(subject) ||
        deny_service_id.count(subject) || deny_publisher.count(subject) ||
        deny_artifact.count(subject) || deny_model.count(subject) ||
        deny_collection.count(subject)) {
        return true;
    }
    return false;
}

void ModelAcl::ObserveProtocolFault(const std::string& subject)
{
    quarantine.insert(subject);
}

bool ModelAcl::Quarantined(const std::string& subject) const
{
    return quarantine.count(subject) > 0;
}

bool ModelAcl::ClearQuarantineFromTrustBundle(const std::string& subject)
{
    (void)subject;
    return false;
}

bool ModelAcl::OperatorClearQuarantine(const std::string& subject)
{
    return quarantine.erase(subject) > 0;
}

void ModelAcl::RecordComplaint(const std::string& subject)
{
    deny_service_id.insert(subject);
}

bool ModelAcl::RecommendationStillOperative(int64_t expires_at, int64_t now) const
{
    return expires_at > now;
}

void ModelAcl::AcceptRevocationTombstone(const std::string& target_id)
{
    revocation_tombstones.insert(target_id);
}

bool ModelAcl::TombstoneRetained(const std::string& target_id) const
{
    return revocation_tombstones.count(target_id) > 0;
}

bool SubscribedWarningIsAutomaticDeny()
{
    return false;
}

bool IdentityAgeCreatesTrust(int64_t age_seconds)
{
    (void)age_seconds;
    return false;
}

bool BalanceCreatesTrust(int64_t balance_atoms)
{
    (void)balance_atoms;
    return false;
}

std::string ResponsibleSource(const std::string& authenticated_peer, const std::string& relay_peer)
{
    (void)relay_peer;
    return authenticated_peer;
}

AclExplanation ExplainExactException(const std::string& rule_id,
                                       const std::string& source,
                                       const std::string& operation,
                                       int64_t expiry)
{
    AclExplanation e;
    e.decision = AclDecision::ALLOW;
    e.rule_id = rule_id;
    e.source = source;
    e.operation = operation;
    e.expiry = expiry;
    return e;
}

std::string PublicAclError(AclDecision d, const std::string& private_contact)
{
    (void)private_contact;
    return AclDecisionName(d);
}

} // namespace modelnet
