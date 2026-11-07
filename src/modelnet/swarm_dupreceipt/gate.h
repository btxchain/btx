// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_GATE_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_GATE_H

#include <modelnet/swarm_dupreceipt/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Refusal code for a Bind that must not store, or empty when the
 * receipt may be stored.
 * An empty receipt is RECEIPT. A receipt already stored is REPLAY.
 * This function does not modify the book.
 */
std::string SwarmDupBindRefusal(const SwarmDupReceiptBook& book, const std::string& receipt);

/**
 * Refusal code for a Pay that must not add atoms, or empty when the
 * pay may credit.
 * An unknown receipt is RECEIPT. atoms below 1 is ATOMS.
 * A receipt already paid is REPLAY. A research key or a scheduler is
 * NOT_SIGNED. A sum that would pass int64 max is ATOMS.
 * Those checks run in that order. This function does not modify the book.
 */
std::string SwarmDupPayRefusal(const SwarmDupReceiptBook& book,
                               const std::string& receipt,
                               int64_t atoms,
                               bool research_key,
                               bool scheduler);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_GATE_H
