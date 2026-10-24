// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSPONSOR_H
#define BTX_MODELNET_SWARM_NOTSPONSOR_H

#include <string>

namespace modelnet {

/**
 * A local note about one admin. want_move_key asks this note to move the
 * sponsor refund key. want_move_height asks this note to move the sponsor
 * refund height.
 *
 * An admin cannot move the sponsor refund key or height. moved and
 * height_changed stay false on every path.
 */
struct SwarmNotSponsor {
    std::string admin_id;
    bool want_move_key{false};
    bool want_move_height{false};
};

/**
 * Outcome of noting an admin. moved and height_changed stay false on every
 * path: an admin cannot move the sponsor refund key or height.
 */
struct SwarmNotSponsorResult {
    std::string code;
    bool moved{false};
    bool height_changed{false};
};

/**
 * Note an admin without moving the sponsor refund key or height.
 * Order, first match wins: an empty admin_id is ADMIN. want_move_key or
 * want_move_height is REFUSED. Otherwise the note is NOTED and err is clear.
 * moved and height_changed stay false on every path. An admin cannot
 * move the sponsor refund key or height.
 */
SwarmNotSponsorResult SwarmNoteNotSponsor(const SwarmNotSponsor& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSPONSOR_H
