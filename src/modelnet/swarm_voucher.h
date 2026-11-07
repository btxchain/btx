// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_VOUCHER_H
#define BTX_MODELNET_SWARM_VOUCHER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one payment voucher. channel_id names the channel
 * the note refers to. sequence is the voucher sequence. stored_sequence
 * is the sequence already stored. amount is the voucher amount.
 * stored_amount is the amount already stored.
 *
 * This note does not accept a voucher. accepted stays false on every
 * path. Nothing is signed and nothing is broadcast. No hostnames or IPs
 * are used.
 */
struct SwarmVoucher {
    std::string channel_id;
    int64_t sequence{0};
    int64_t stored_sequence{0};
    int64_t amount{0};
    int64_t stored_amount{0};
};

/**
 * Outcome of noting a voucher. accepted stays false on every path:
 * nothing is signed and nothing is broadcast.
 */
struct SwarmVoucherResult {
    bool accepted{false};
    std::string code;
};

/**
 * Note a voucher without accepting it.
 * Order, first match wins: an empty channel_id, sequence below 1,
 * stored_sequence below 1, amount below 0, or stored_amount below 0 is
 * VOUCHER. sequence below stored_sequence is STALE_VOUCHER, even when
 * amount is also below stored_amount. amount below stored_amount is
 * DECREASING_PAYMENT. Otherwise the note is NOTED and err is clear.
 * An equal or higher sequence with an equal or higher amount is still
 * not accepted. accepted stays false on every path. Nothing is signed
 * and nothing is broadcast.
 */
SwarmVoucherResult SwarmNoteVoucher(const SwarmVoucher& voucher, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_VOUCHER_H
