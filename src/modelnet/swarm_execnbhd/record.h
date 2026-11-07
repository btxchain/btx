// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_RECORD_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One offered peer. peer and trust_domain are opaque ids.
 * A record is admitted only when the peer id and the trust domain are
 * non-empty, rtt_ms is at least 0, and both flags are true.
 */
struct SwarmExecNbhdRecord {
    std::string peer;
    int64_t rtt_ms{0};
    std::string trust_domain;
    bool authorized{false};
    bool compatible{false};
};

inline bool SwarmExecNbhdRecordAdmitted(const SwarmExecNbhdRecord& row)
{
    return !row.peer.empty() && row.rtt_ms >= 0 && !row.trust_domain.empty() && row.authorized && row.compatible;
}

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_RECORD_H
