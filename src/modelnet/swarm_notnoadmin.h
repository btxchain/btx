// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOADMIN_H
#define BTX_MODELNET_SWARM_NOTNOADMIN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one admin. want_move_refund asks this note to move a
 * sponsor refund key or height.
 *
 * An admin note does not move a sponsor refund key or height. moved stays
 * false and height stays 0 on every path.
 */
struct SwarmNotNoAdmin {
    std::string admin_id;
    bool want_move_refund{false};
};

/**
 * Outcome of noting an admin. moved stays false and height stays 0 on
 * every path: an admin note does not move a sponsor refund key or height.
 */
struct SwarmNotNoAdminResult {
    std::string code;
    bool moved{false};
    int64_t height{0};
};

/**
 * Note an admin without moving a sponsor refund key or height.
 * Order, first match wins: an empty admin_id is ADMIN. want_move_refund
 * is REFUSED. Otherwise the note is NOTED and err is cleared.
 * moved stays false and height stays 0 on every path. An admin note does
 * not move a sponsor refund key or height.
 */
SwarmNotNoAdminResult SwarmNoteNotNoAdmin(const SwarmNotNoAdmin& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOADMIN_H
