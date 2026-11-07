// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODUPRECEIPT_H
#define BTX_MODELNET_SWARM_NOTNODUPRECEIPT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one receipt. duplicate marks the receipt as already
 * seen. want_book asks this note to book it.
 *
 * A duplicate receipt is not booked twice and pays nothing.
 * booked stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoDupReceipt {
    std::string receipt_id;
    bool duplicate{false};
    bool want_book{false};
};

/**
 * Outcome of noting a receipt. booked stays false and atoms stays 0 on
 * every path: a duplicate receipt is not booked twice and pays nothing.
 */
struct SwarmNotNoDupReceiptResult {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

/**
 * Note a receipt without booking it twice or paying.
 * Order, first match wins: an empty receipt_id is RECEIPT.
 * If duplicate is true, the note is DUPLICATE even when want_book is false.
 * want_book is HELD. Otherwise the note is NOTED and err is cleared.
 * booked stays false and atoms stays 0 on every path. A duplicate receipt
 * is not booked twice and pays nothing.
 */
SwarmNotNoDupReceiptResult SwarmNoteNotNoDupReceipt(const SwarmNotNoDupReceipt& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODUPRECEIPT_H
