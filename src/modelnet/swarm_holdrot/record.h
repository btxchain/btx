// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_RECORD_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One recorded holdout.
 * The record holds the label only. rotated stays false.
 * bytes_moved stays 0. gpu stays false. launched stays false.
 * Make is the only writer of those fields. There is no setter
 * and no method that marks the holdout rotating.
 */
class SwarmHoldoutRotateRecord {
public:
    static SwarmHoldoutRotateRecord Make(const std::string& holdout);

    const std::string& holdout() const { return m_holdout; }
    bool rotated() const { return m_rotated; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool gpu() const { return m_gpu; }
    bool launched() const { return m_launched; }

private:
    std::string m_holdout;
    bool m_rotated{false};
    int64_t m_bytes_moved{0};
    bool m_gpu{false};
    bool m_launched{false};
};

/**
 * The holdout is non-empty, the record is not rotating, no bytes moved,
 * the gpu is idle, and nothing was launched.
 */
bool SwarmHoldoutRotateRecordUsable(const SwarmHoldoutRotateRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_RECORD_H
