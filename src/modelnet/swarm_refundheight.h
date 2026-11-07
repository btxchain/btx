// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REFUNDHEIGHT_H
#define BTX_MODELNET_SWARM_REFUNDHEIGHT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one sponsor lot. height is the noted refund height.
 * want_change_height asks this note to move the sponsor refund height.
 * admin does not grant that move.
 *
 * This note does not move the sponsor refund height, does not sign, and
 * does not broadcast. changed stays false on every path. No hostnames or
 * IPs are used.
 */
struct SwarmRefundHeightMove {
    std::string lot_id;
    int64_t height{0};
    bool admin{false};
    bool want_change_height{false};
};

/**
 * Outcome of noting a refund-height move. changed stays false: an admin
 * cannot move the sponsor refund height. Nothing is signed and nothing
 * is broadcast.
 */
struct SwarmRefundHeightResult {
    bool changed{false};
    std::string code;
};

/**
 * Note a refund-height move without moving the sponsor refund height.
 * Order, first match wins: an empty lot_id or height below 1 is HEIGHT.
 * A request to change the refund height is IMMUTABLE, even when admin is
 * true. Otherwise the note is NOTED and err is cleared. changed stays
 * false on every path. An admin cannot move the sponsor refund height.
 * Nothing is signed and nothing is broadcast.
 */
SwarmRefundHeightResult SwarmNoteRefundHeight(const SwarmRefundHeightMove& move, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REFUNDHEIGHT_H
