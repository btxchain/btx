// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_RECORD_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_RECORD_H

#include <cstdint>

namespace modelnet {

/**
 * One recorded shrink request.
 * The record holds the block count only. shrunk stays false.
 * bytes_moved stays 0. gpu stays false. launched stays false.
 * mined stays false.
 * Make is the only writer of those fields. There is no setter
 * and no shrink method.
 */
class SwarmCloseMarginHoldRecord {
public:
    static SwarmCloseMarginHoldRecord Make(int64_t blocks);

    int64_t blocks() const { return m_blocks; }
    bool shrunk() const { return m_shrunk; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool gpu() const { return m_gpu; }
    bool launched() const { return m_launched; }
    bool mined() const { return m_mined; }

private:
    int64_t m_blocks{0};
    bool m_shrunk{false};
    int64_t m_bytes_moved{0};
    bool m_gpu{false};
    bool m_launched{false};
    bool m_mined{false};
};

/**
 * The block count is 160, the margin is not shrunk, no bytes moved,
 * the gpu is idle, nothing was launched, and nothing was mined.
 */
bool SwarmCloseMarginHoldRecordUsable(const SwarmCloseMarginHoldRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_RECORD_H
