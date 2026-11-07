// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_RECORD_H
#define BITCOIN_MODELNET_SWARM_RESCAP_RECORD_H

#include <cstdint>

namespace modelnet {

/**
 * One recorded thread count.
 * The record holds the count only. raised stays false.
 * bytes_moved stays 0. gpu stays false. launched stays false.
 * Make is the only writer of those fields. There is no setter
 * and no method that raises a sandbox limit.
 */
class SwarmResCapRecord {
public:
    static SwarmResCapRecord Make(int64_t threads);

    int64_t threads() const { return m_threads; }
    bool raised() const { return m_raised; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool gpu() const { return m_gpu; }
    bool launched() const { return m_launched; }

private:
    int64_t m_threads{0};
    bool m_raised{false};
    int64_t m_bytes_moved{0};
    bool m_gpu{false};
    bool m_launched{false};
};

/**
 * The count is from 1 through 64, the record is not raised, no bytes moved,
 * the gpu is idle, and nothing was launched.
 */
bool SwarmResCapRecordUsable(const SwarmResCapRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_RECORD_H
