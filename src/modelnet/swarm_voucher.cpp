// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_voucher.h>

#include <cstdint>

namespace modelnet {

SwarmVoucherResult SwarmNoteVoucher(const SwarmVoucher& voucher, std::string& err)
{
    SwarmVoucherResult result;
    result.accepted = false;
    if (voucher.channel_id.empty() || voucher.sequence < 1 || voucher.stored_sequence < 1 ||
        voucher.amount < 0 || voucher.stored_amount < 0) {
        result.code = "VOUCHER";
        result.accepted = false;
        err = "VOUCHER";
        return result;
    }
    // A lower sequence is stale even when the amount is also lower.
    // Nothing is signed and nothing is broadcast.
    if (voucher.sequence < voucher.stored_sequence) {
        result.code = "STALE_VOUCHER";
        result.accepted = false;
        err = "STALE_VOUCHER";
        return result;
    }
    if (voucher.amount < voucher.stored_amount) {
        result.code = "DECREASING_PAYMENT";
        result.accepted = false;
        err = "DECREASING_PAYMENT";
        return result;
    }
    // An equal or higher sequence with an equal or higher amount is still
    // not accepted by this note. Nothing is signed and nothing is broadcast.
    result.code = "NOTED";
    result.accepted = false;
    err.clear();
    return result;
}

} // namespace modelnet
