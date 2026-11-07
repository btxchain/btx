// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTJOURNAL_H
#define BTX_MODELNET_SWARM_FAULTJOURNAL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Applies one of the twenty acceptance faults by calling the existing
 * recovery functions. Earned atoms stay put. Bytes stay at zero. This is
 * not a live injection and it does not spend or broadcast.
 *
 * 1 coordinator gone, 2 replacement during expiry, 3 stale epoch,
 * 4 checkpoint publication crash, 5 worker disconnect, 6 duplicate receipt,
 * 7 cache owner gone, 8 truncated cache, 9 partial piece,
 * 10 promotion interrupted, 11 canary regression, 12 conflicting evaluators,
 * 13 payment crash after earn, 14 refund maturity, 15 reorg exit,
 * 16 collateral reuse, 17 revoked cache, 18 withdrawn dataset,
 * 19 false compatibility, 20 permanent coordinator loss.
 */
class SwarmFaultJournal {
public:
    void Arm(int64_t earned_atoms, bool checkpoint, bool payment_plane, bool durable);

    bool Apply(int fault, std::string& err);

    int64_t earned_atoms() const { return m_earned; }
    int64_t bytes_moved() const { return m_bytes; }
    bool frozen() const { return m_frozen; }
    bool training() const { return m_training; }
    bool report_accepted() const { return m_accepted; }
    const std::string& code() const { return m_code; }

private:
    int64_t m_earned{0};
    int64_t m_bytes{0};
    bool m_checkpoint{false};
    bool m_payment_plane{false};
    bool m_durable{false};
    bool m_frozen{false};
    bool m_training{false};
    bool m_accepted{false};
    std::string m_code;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTJOURNAL_H
