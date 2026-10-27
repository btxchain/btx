// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_CERTIFICATE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_CERTIFICATE_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationCertificateRow {
    std::string candidate_id;
    int cycle{0};
};

/**
 * Promotion certificates. A certificate does not admit exact replay
 * and does not promote a realm.
 */
class SwarmGenerationCertificates {
public:
    bool promoted(const std::string& candidate_id) const;
    void add(std::string candidate_id, int cycle);
    std::size_t count() const { return m_rows.size(); }
    const std::vector<SwarmGenerationCertificateRow>& rows() const { return m_rows; }

private:
    std::vector<SwarmGenerationCertificateRow> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_CERTIFICATE_H
