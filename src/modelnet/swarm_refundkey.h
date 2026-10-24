// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REFUNDKEY_H
#define BTX_MODELNET_SWARM_REFUNDKEY_H

#include <string>

namespace modelnet {

/**
 * A local note about one sponsor lot. want_move_refund_key asks this
 * note to move the sponsor refund key. admin does not grant that move.
 *
 * This note does not move the sponsor refund key, does not sign, and
 * does not broadcast. No hostnames, IPs, or key material are used.
 */
struct SwarmRefundKeyMove {
    std::string lot_id;
    bool admin{false};
    bool want_move_refund_key{false};
};

/**
 * Outcome of noting a refund-key move. moved stays false: an admin
 * cannot move the sponsor refund key. Nothing is signed and nothing
 * is broadcast.
 */
struct SwarmRefundKeyResult {
    bool moved{false};
    std::string code;
};

/**
 * Note a refund-key move without moving the sponsor refund key.
 * Order, first match wins: an empty lot_id is REFUND. A request to
 * move the refund key is IMMUTABLE, even when admin is true. Otherwise
 * the note is NOTED and err is cleared. moved stays false on every
 * path. An admin cannot move the sponsor refund key. Nothing is signed
 * and nothing is broadcast.
 */
SwarmRefundKeyResult SwarmNoteRefundKey(const SwarmRefundKeyMove& move, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REFUNDKEY_H
