// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREFUNDKEY2_H
#define BTX_MODELNET_SWARM_NOTNOREFUNDKEY2_H

#include <string>

namespace modelnet {

/**
 * A local admin note. want_move asks this note to move the sponsor
 * refund key.
 *
 * An admin note does not move the sponsor refund key. moved stays
 * false on every path.
 */
struct SwarmNotNoRefundKey2 {
    std::string admin_id;
    bool want_move{false};
};

/**
 * Outcome of noting an admin. moved stays false on every path.
 * An admin note does not move the sponsor refund key.
 */
struct SwarmNotNoRefundKey2Result {
    std::string code;
    bool moved{false};
};

/**
 * Note an admin without moving the sponsor refund key. Order, first
 * match wins: an empty admin_id is ADMIN. want_move is HELD. Otherwise
 * the note is NOTED and err is cleared. moved stays false on every
 * path. An admin note does not move the sponsor refund key.
 */
SwarmNotNoRefundKey2Result SwarmNoteNotNoRefundKey2(const SwarmNotNoRefundKey2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREFUNDKEY2_H
