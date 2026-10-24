// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_BOOK_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_BOOK_H

#include <modelnet/swarm_dupreceipt/earned.h>
#include <modelnet/swarm_dupreceipt/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Receipts stored by a successful Bind, keyed by receipt id.
 * store refuses an empty receipt and a receipt already present.
 * credit adds atoms once. A second credit does not add again.
 * A research key or a scheduler is refused and the row stays unpaid.
 * A refused store or credit leaves the first row and earned unchanged.
 */
class SwarmDupReceiptBook {
public:
    bool contains(const std::string& receipt) const;
    bool paid(const std::string& receipt) const;
    int64_t paid_atoms(const std::string& receipt) const;
    int64_t earned() const;
    std::size_t size() const;

    /**
     * Store an unpaid receipt. Refuses an empty id and a duplicate.
     * On refusal the book is unchanged. Atoms are not added.
     */
    bool store(const std::string& receipt);

    /**
     * Add atoms for one bound receipt.
     * Refuses an unknown receipt, atoms below 1, a receipt already paid,
     * a research key, a scheduler, and a sum that would pass int64 max.
     * On refusal earned and the stored atoms stay as they were.
     */
    bool credit(const std::string& receipt, int64_t atoms, bool research_key, bool scheduler);

private:
    std::map<std::string, SwarmDupReceiptRow> m_rows;
    SwarmDupEarned m_earned;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_BOOK_H
