// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOADMINMOVE2_H
#define BTX_MODELNET_SWARM_NOTNOADMINMOVE2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one refund. refund_id names the refund.
 * admin is whether the note is an admin. want_move asks this note to
 * move a sponsor refund key or height.
 *
 * An admin cannot move a sponsor refund key or height. moved stays
 * false and height stays 0 on every path.
 */
struct SwarmNotNoAdminMove2 {
    std::string refund_id;
    bool admin{false};
    bool want_move{false};
};

/**
 * Outcome of noting a refund. moved stays false and height stays 0 on
 * every path: an admin cannot move a sponsor refund key or height.
 */
struct SwarmNotNoAdminMove2Result {
    std::string code;
    bool moved{false};
    int64_t height{0};
};

/**
 * Note a refund without moving a sponsor refund key or height.
 * Order, first match wins: an empty refund_id is REFUND. admin true is
 * NOT_MOVED, even when want_move is false. want_move is HELD. Otherwise
 * the note is NOTED and err is cleared. moved stays false and height
 * stays 0 on every path. An admin cannot move a sponsor refund key or
 * height.
 */
SwarmNotNoAdminMove2Result SwarmNoteNotNoAdminMove2(const SwarmNotNoAdminMove2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOADMINMOVE2_H
