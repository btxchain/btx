// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/certificate.h>

#include <utility>

namespace modelnet {

bool SwarmGenerationCertificates::promoted(const std::string& candidate_id) const
{
    for (const SwarmGenerationCertificateRow& row : m_rows) {
        if (row.candidate_id == candidate_id) return true;
    }
    return false;
}

void SwarmGenerationCertificates::add(std::string candidate_id, int cycle)
{
    if (promoted(candidate_id)) return;
    SwarmGenerationCertificateRow row;
    row.candidate_id = std::move(candidate_id);
    row.cycle = cycle;
    m_rows.push_back(std::move(row));
}

} // namespace modelnet
