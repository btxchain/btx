// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/certificate.h>

#include <modelnet/swarm_evalengine/limits.h>

namespace modelnet {

bool SwarmEvaluationCertificateBook::contains(const std::string& candidate) const
{
    return m_rows.find(candidate) != m_rows.end();
}

bool SwarmEvaluationCertificateBook::money(const std::string& candidate) const
{
    const auto it = m_rows.find(candidate);
    if (it == m_rows.end()) {
        return kSwarmEvaluationMoney;
    }
    return it->second.money;
}

bool SwarmEvaluationCertificateBook::realm_promoted(const std::string& candidate) const
{
    const auto it = m_rows.find(candidate);
    if (it == m_rows.end()) {
        return kSwarmEvaluationRealmPromoted;
    }
    return it->second.realm_promoted;
}

bool SwarmEvaluationCertificateBook::exact_replay_admitted(const std::string& candidate) const
{
    const auto it = m_rows.find(candidate);
    if (it == m_rows.end()) {
        return kSwarmEvaluationExactReplayAdmitted;
    }
    return it->second.exact_replay_admitted;
}

bool SwarmEvaluationCertificateBook::store(const std::string& candidate)
{
    if (candidate.empty() || contains(candidate)) {
        return false;
    }
    SwarmEvaluationCertificate certificate;
    certificate.candidate = candidate;
    certificate.money = kSwarmEvaluationMoney;
    certificate.realm_promoted = kSwarmEvaluationRealmPromoted;
    certificate.exact_replay_admitted = kSwarmEvaluationExactReplayAdmitted;
    m_rows.emplace(candidate, certificate);
    return true;
}

} // namespace modelnet
