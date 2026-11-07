// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_RECORD_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One recorded checkpoint claim.
 * The record holds the claim only. trusted stays false.
 * A checkpoint-only claim is not lineage authority.
 * bytes_moved stays 0. gpu stays false. launched stays false.
 * Make is the only writer of those fields. There is no setter
 * and no method that marks the claim trusted.
 */
class SwarmCheckpointTrustRecord {
public:
    static SwarmCheckpointTrustRecord Make(const std::string& claim);

    const std::string& claim() const { return m_claim; }
    bool trusted() const { return m_trusted; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool gpu() const { return m_gpu; }
    bool launched() const { return m_launched; }

private:
    std::string m_claim;
    bool m_trusted{false};
    int64_t m_bytes_moved{0};
    bool m_gpu{false};
    bool m_launched{false};
};

/**
 * The claim is non-empty, the record is not trusted, no bytes moved,
 * the gpu is idle, and nothing was launched.
 */
bool SwarmCheckpointTrustRecordUsable(const SwarmCheckpointTrustRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_RECORD_H
