// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_TRUST_H
#define BITCOIN_MODELNET_SECURITY_V2_TRUST_H
#include <modelnet/security_v2/database.h>
#include <map>
#include <set>
namespace modelnet::security {
struct Principal {
    Bytes key;
    std::set<std::string> roles;
    std::string domain, host, transport_pin;
};
struct Policy {
    Json envelope;
    std::string id, realm;
    uint64_t epoch{0}, expires{0};
    size_t release_threshold{2}, evaluator_domains{2}, physical_hosts{2};
    uint64_t evidence_ttl_ms{3600000}, canary_ms{60000}, trial_limit{16};
    std::map<std::string,Principal> principals;
    std::vector<std::string> gates;
    static Policy Load(Database& db, int64_t now);
    static Policy Decode(const Json& envelope);
    const Principal& Find(const std::string& key_id, std::string_view role, Database& db, int64_t now) const;
    std::vector<std::string> Check(const Json& envelope, std::string_view role,
                                   Database& db, int64_t now, size_t threshold = 1) const;
};
void VerifyPinnedPolicy(const Json& policy, const Json& roots);
void InstallPolicy(Database& db, const Json& envelope, int64_t now);
void ValidateComposition(const Json& composition);
struct Admission {
    std::string capsule_id, composition_id, runtime, tool_schema, policy_id, profile;
    uint64_t epoch{0}, valid_until{0};
    std::set<std::string> evaluator_keys, domains, hosts;
};
Admission AdmitCapsule(Database& db, const Policy& policy, const std::string& capsule_id, int64_t now);
void ImportRecord(Database& db, const Policy& policy, const Json& envelope, int64_t now, bool from_peer = false);
Json SecurityStatus(Database& db, const Policy& policy, const std::string& subject, int64_t now);
} // namespace modelnet::security
#endif
