// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CLOSEREFUND_H
#define BTX_MODELNET_SWARM_CLOSEREFUND_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A close-template record. channel_id names the channel. margin is the
 * offered close margin. want_shrink asks this record to shrink.
 * want_broadcast asks this record to broadcast.
 *
 * The close margin stays 160 blocks. This record does not broadcast.
 * It does not spend. No hostname, IP, or key path.
 */
struct SwarmCloseRefund {
    std::string channel_id;
    int64_t margin{0};
    bool want_shrink{false};
    bool want_broadcast{false};
};

/**
 * Outcome of recording a close template. shrunk stays false, broadcast
 * stays false, and blocks stays 160 on every path.
 * The close margin stays 160 blocks. This record does not broadcast.
 */
struct SwarmCloseRefundResult {
    std::string code;
    bool shrunk{false};
    bool broadcast{false};
    int64_t blocks{160};
};

/**
 * Record a close template without broadcasting or spending.
 * Order, first match wins: an empty channel_id is CHANNEL. A margin
 * other than 160 is MARGIN. want_shrink or want_broadcast is HELD.
 * Otherwise the record is NOTED and err is cleared.
 * shrunk stays false, broadcast stays false, and blocks stays 160 on
 * every path.
 * The close margin stays 160 blocks. This record does not broadcast.
 */
SwarmCloseRefundResult SwarmRecordClose(const SwarmCloseRefund& close, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CLOSEREFUND_H
