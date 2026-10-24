// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTADMIN_H
#define BTX_MODELNET_SWARM_NOTADMIN_H

#include <string>

namespace modelnet {

/**
 * A local note about one admin. want_move asks this note to move a sponsor
 * refund key or refund height.
 *
 * An admin cannot move a sponsor refund key or refund height. moved and
 * height_changed stay false on every path.
 */
struct SwarmNotAdmin {
    std::string admin_id;
    bool want_move{false};
};

/**
 * Outcome of noting an admin. moved and height_changed stay false on every
 * path: an admin cannot move a sponsor refund key or refund height.
 */
struct SwarmNotAdminResult {
    std::string code;
    bool moved{false};
    bool height_changed{false};
};

/**
 * Note an admin without moving a sponsor refund key or refund height.
 * Order, first match wins: an empty admin_id is ADMIN. want_move is
 * REFUSED. Otherwise the note is NOTED and err is clear.
 * moved and height_changed stay false on every path. An admin cannot
 * move a sponsor refund key or refund height.
 */
SwarmNotAdminResult SwarmNoteNotAdmin(const SwarmNotAdmin& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTADMIN_H
