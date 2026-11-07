// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPROVISIONAL_H
#define BTX_MODELNET_SWARM_NOTNOPROVISIONAL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one receipt. provisional marks the receipt as not
 * yet final. want_book asks this note to book it.
 *
 * A provisional receipt is not a final booking and pays nothing.
 * booked stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoProvisional {
    std::string receipt_id;
    bool provisional{false};
    bool want_book{false};
};

/**
 * Outcome of noting a receipt. booked stays false and atoms stays 0 on
 * every path: a provisional receipt is not a final booking and pays nothing.
 */
struct SwarmNotNoProvisionalResult {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

/**
 * Note a receipt without treating a provisional receipt as a final booking.
 * Order, first match wins: an empty receipt_id is RECEIPT.
 * If provisional is true, the note is NOT_FINAL even when want_book is false.
 * want_book is HELD. Otherwise the note is NOTED and err is cleared.
 * booked stays false and atoms stays 0 on every path. A provisional receipt
 * is not a final booking and pays nothing.
 */
SwarmNotNoProvisionalResult SwarmNoteNotNoProvisional(const SwarmNotNoProvisional& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPROVISIONAL_H
