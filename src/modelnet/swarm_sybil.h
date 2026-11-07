// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SYBIL_H
#define BTX_MODELNET_SWARM_SYBIL_H

#include <map>
#include <set>
#include <string>

namespace modelnet {

/**
 * One swarm member. A member needs a non-empty member id, a non-empty
 * key id distinct from that member id, and a non-empty trust domain.
 * admitted starts false.
 */
struct SwarmSybilMember {
    std::string member_id;
    std::string key_id;
    std::string trust_domain;
    bool admitted{false};
};

/**
 * Field gate for one member. This function does not store the member.
 *
 * Order: an empty member id, key id, or trust domain is SYBIL. A key id
 * equal to the member id is SYBIL. admitted starts false and stays false
 * on those refusals. Otherwise the three fields are copied, admitted is
 * set, and err is cleared.
 */
SwarmSybilMember SwarmAdmitMember(const std::string& member_id, const std::string& key_id,
                                  const std::string& trust_domain, std::string& err);

/**
 * In-memory member book. A key id belongs to one member. admitted starts
 * false and is set only when a member is stored or idempotently admitted.
 */
class SwarmSybilBook {
public:
    /**
     * Order: an empty member id, key id, or trust domain is SYBIL. A key
     * id equal to the member id is SYBIL. Nothing is stored for those.
     * The same member id again with the same key and domain is idempotent
     * and admitted. The same member id with a different key or domain is
     * REPLAY and the first record stays. A second member reusing the same
     * key id is SYBIL and is not stored.
     */
    bool Admit(const std::string& member_id, const std::string& key_id, const std::string& trust_domain,
               std::string& err);

    /** Stored members. */
    int Count() const;

    /** Distinct trust domains among stored members. */
    int Domains() const;

private:
    struct Record {
        std::string key_id;
        std::string trust_domain;
        bool admitted{false};
    };

    std::map<std::string, Record> m_members;
    std::set<std::string> m_domains;
    std::map<std::string, std::string> m_key_owner;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SYBIL_H
