// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_H

#include <modelnet/swarm_dupreceipt/book.h>
#include <modelnet/swarm_dupreceipt/quiet.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Duplicate-receipt plane.
 * A receipt is paid once. A second arrival does not add atoms.
 *
 * Bind stores a receipt. An empty receipt is RECEIPT and stores nothing.
 * A second Bind of the same receipt is REPLAY and keeps the first.
 *
 * Pay adds atoms to the earned counter once.
 * An unknown receipt is RECEIPT and adds nothing.
 * atoms below 1 is ATOMS and adds nothing.
 * The first Pay of a bound receipt adds atoms and returns true.
 * A second Pay of that receipt is REPLAY and leaves earned unchanged.
 * A research key or a scheduler is NOT_SIGNED and leaves the receipt unpaid.
 * A sum that would pass int64 max is ATOMS and leaves the receipt unpaid.
 * Those Pay checks run in that order.
 *
 * automatic_spend() stays "0". broadcast() stays false.
 * mined() stays false. bytes_moved() stays 0.
 */
class SwarmDupReceipt {
public:
    bool Bind(const std::string& receipt, std::string& err);
    bool Pay(const std::string& receipt, int64_t atoms, bool research_key, bool scheduler, std::string& err);

    bool bound(const std::string& receipt) const;
    bool paid(const std::string& receipt) const;
    int64_t earned() const;
    int64_t paid_atoms(const std::string& receipt) const;
    std::size_t bound_count() const;

    bool broadcast() const;
    bool mined() const;
    int64_t bytes_moved() const;
    std::string automatic_spend() const;

private:
    SwarmDupReceiptBook m_book;
    SwarmDupQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_H
