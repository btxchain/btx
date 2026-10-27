// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RECEIPTBOOK_H
#define BITCOIN_MODELNET_SWARM_RECEIPTBOOK_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmReceiptRequest {
    std::string receipt_id;
    bool provisional{false};
    bool want_book{false};
};

struct SwarmReceiptBookResult {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

SwarmReceiptBookResult SwarmNoteReceipt(const SwarmReceiptRequest& receipt, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RECEIPTBOOK_H
