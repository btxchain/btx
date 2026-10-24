// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CLOSEMARGIN_H
#define BTX_MODELNET_SWARM_CLOSEMARGIN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one channel close margin. channel_id names the
 * channel. height is the noted height. refund_height is the refund
 * height. close_margin is the offered close margin. The required margin
 * is 160. want_new_work asks this note to start new work.
 *
 * New work stops inside the close margin. This note does not start work
 * and does not broadcast. work_started stays false on every path. No
 * hostnames or IPs are used.
 */
struct SwarmCloseMargin {
    std::string channel_id;
    int64_t height{0};
    int64_t refund_height{0};
    int64_t close_margin{0};
    bool want_new_work{false};
};

/**
 * Outcome of noting a close margin. work_started stays false: this note
 * does not start work and does not broadcast.
 */
struct SwarmCloseMarginResult {
    bool work_started{false};
    std::string code;
};

/**
 * Note a close margin without starting work.
 * Order, first match wins: an empty channel_id, a height below 0, or a
 * refund_height below 1 is MARGIN. A close_margin other than the required
 * margin of 160 is MARGIN_REFUSED, including when want_new_work is true.
 * height + close_margin at or beyond refund_height is STOP, including
 * when want_new_work is true. Equality stops. New work stops inside the
 * close margin. want_new_work is HELD and err is cleared. Otherwise the
 * note is NOTED and err is cleared.
 * work_started stays false on every path. Nothing is broadcast.
 */
SwarmCloseMarginResult SwarmNoteCloseMargin(const SwarmCloseMargin& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CLOSEMARGIN_H
