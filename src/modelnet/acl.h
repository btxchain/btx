// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACL_H
#define BITCOIN_MODELNET_ACL_H

#include <modelnet/policy.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace modelnet {

enum class PolicyDim : uint8_t {
    CONNECT = 0,
    DISCOVER = 1,
    RETRIEVE = 2,
    SERVE = 3,
    TRUST_METADATA = 4,
    AUTO_SEED = 5,
    AUTO_PAY = 6,
};

struct AclExplanation {
    AclDecision decision{AclDecision::ALLOW};
    std::string rule_id;
    std::string source;
    std::string operation;
    int64_t expiry{0};
};

struct ModelAcl {
    std::unordered_set<std::string> deny_endpoint;
    std::unordered_set<std::string> deny_subnet;
    std::unordered_set<std::string> deny_service_id;
    std::unordered_set<std::string> deny_publisher;
    std::unordered_set<std::string> deny_artifact;
    std::unordered_set<std::string> deny_model;
    std::unordered_set<std::string> deny_collection;
    std::unordered_set<std::string> allow_prefer;
    std::unordered_set<std::string> quarantine;
    std::unordered_set<std::string> revocation_tombstones;
    bool auto_seed{false};
    bool auto_pay{false};
    bool trust_metadata{false};

    bool Denied(PolicyDim dim, const std::string& subject) const;
    /** Model ACLs never map to monetary BanMan / NoBan / ForceRelay. */
    bool AffectsMonetaryBan() const { return false; }
    bool AffectsAddrMan() const { return false; }
    bool WritesBanMan() const { return false; }
    int64_t AutomaticSpendAtoms() const { return 0; }

    void ObserveProtocolFault(const std::string& subject);
    bool Quarantined(const std::string& subject) const;
    bool ClearQuarantineFromTrustBundle(const std::string& subject);
    bool OperatorClearQuarantine(const std::string& subject);
    void RecordComplaint(const std::string& subject);
    bool RecommendationStillOperative(int64_t expires_at, int64_t now) const;
    void AcceptRevocationTombstone(const std::string& target_id);
    bool TombstoneRetained(const std::string& target_id) const;
};

bool SubscribedWarningIsAutomaticDeny();
bool IdentityAgeCreatesTrust(int64_t age_seconds);
bool BalanceCreatesTrust(int64_t balance_atoms);
std::string ResponsibleSource(const std::string& authenticated_peer, const std::string& relay_peer);
AclExplanation ExplainExactException(const std::string& rule_id,
                                       const std::string& source,
                                       const std::string& operation,
                                       int64_t expiry);
std::string PublicAclError(AclDecision d, const std::string& private_contact);

} // namespace modelnet

#endif // BITCOIN_MODELNET_ACL_H
