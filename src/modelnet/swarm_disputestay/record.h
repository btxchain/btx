// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_RECORD_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One opened dispute.
 * The record holds the dispute id only. settled stays false.
 * atoms_moved stays 0. bytes_moved stays 0.
 * broadcast stays false. mined stays false.
 * Make is the only writer of those fields. There is no setter
 * and no settle method.
 */
class SwarmDisputeStayRecord {
public:
    static SwarmDisputeStayRecord Make(const std::string& dispute);

    const std::string& dispute() const { return m_dispute; }
    bool settled() const { return m_settled; }
    int64_t atoms_moved() const { return m_atoms_moved; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool broadcast() const { return m_broadcast; }
    bool mined() const { return m_mined; }

private:
    std::string m_dispute;
    bool m_settled{false};
    int64_t m_atoms_moved{0};
    int64_t m_bytes_moved{0};
    bool m_broadcast{false};
    bool m_mined{false};
};

/**
 * The id is non-empty, the dispute is not settled, no atoms moved,
 * no bytes moved, nothing was broadcast, and nothing was mined.
 */
bool SwarmDisputeStayRecordUsable(const SwarmDisputeStayRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_RECORD_H
