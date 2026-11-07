// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sybil.h>

namespace modelnet {

SwarmSybilMember SwarmAdmitMember(const std::string& member_id, const std::string& key_id,
                                  const std::string& trust_domain, std::string& err)
{
    SwarmSybilMember member;
    member.admitted = false;
    if (member_id.empty() || key_id.empty() || trust_domain.empty() || key_id == member_id) {
        err = "SYBIL";
        return member;
    }
    member.member_id = member_id;
    member.key_id = key_id;
    member.trust_domain = trust_domain;
    member.admitted = true;
    err.clear();
    return member;
}

bool SwarmSybilBook::Admit(const std::string& member_id, const std::string& key_id, const std::string& trust_domain,
                           std::string& err)
{
    const SwarmSybilMember gate = SwarmAdmitMember(member_id, key_id, trust_domain, err);
    if (!gate.admitted) {
        return false;
    }
    const auto existing = m_members.find(member_id);
    if (existing != m_members.end()) {
        if (existing->second.key_id == key_id && existing->second.trust_domain == trust_domain) {
            existing->second.admitted = true;
            err.clear();
            return true;
        }
        err = "REPLAY";
        return false;
    }
    const auto key = m_key_owner.find(key_id);
    if (key != m_key_owner.end()) {
        err = "SYBIL";
        return false;
    }
    Record record;
    record.key_id = key_id;
    record.trust_domain = trust_domain;
    record.admitted = true;
    m_members.emplace(member_id, record);
    m_key_owner.emplace(key_id, member_id);
    m_domains.insert(trust_domain);
    err.clear();
    return true;
}

int SwarmSybilBook::Count() const
{
    return static_cast<int>(m_members.size());
}

int SwarmSybilBook::Domains() const
{
    return static_cast<int>(m_domains.size());
}

} // namespace modelnet
