// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_receiptbook.h>

namespace modelnet {

SwarmReceiptBookResult SwarmNoteReceipt(const SwarmReceiptRequest& receipt, std::string& err)
{
    // A provisional receipt is not a final booking.
    SwarmReceiptBookResult result;
    result.booked = false;
    result.atoms = 0;

    if (receipt.receipt_id.empty()) {
        result.code = "RECEIPT";
        err = "RECEIPT";
        return result;
    }
    if (receipt.provisional) {
        result.code = "PROVISIONAL";
        err = "PROVISIONAL";
        return result;
    }
    if (receipt.want_book) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }

    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
