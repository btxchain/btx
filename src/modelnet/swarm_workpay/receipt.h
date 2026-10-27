// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WORKPAY_RECEIPT_H
#define BITCOIN_MODELNET_SWARM_WORKPAY_RECEIPT_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** One first bind. A replay does not replace job or atoms. */
struct SwarmWorkReceipt {
    std::string job;
    int64_t atoms{0};
};

/**
 * In-memory work receipts. Bind stores a receipt once.
 * total() is the sum of those first binds. A failed bind stores nothing.
 */
class SwarmWorkReceiptBook {
public:
    /**
     * Empty receipt or empty job is RECEIPT and stores nothing.
     * atoms below 1 is ATOMS and stores nothing.
     * The same receipt again is REPLAY and does not add atoms again.
     * A sum that would pass int64 max is ATOMS and stores nothing.
     * Otherwise the receipt, job, and atoms are stored and total grows
     * by atoms.
     */
    bool Bind(const std::string& receipt, const std::string& job, int64_t atoms, std::string& err);

    /** Sum of atoms from binds that stored a receipt. */
    int64_t total() const;

    /** True when this receipt was stored by a successful Bind. */
    bool bound(const std::string& receipt) const;

    /**
     * On success, atoms is the stored amount.
     * An unknown receipt, including one that failed Bind, returns false
     * and leaves atoms unchanged.
     */
    bool Find(const std::string& receipt, int64_t& atoms) const;

    /**
     * On success, job and atoms are the first bind.
     * An unknown receipt returns false and leaves both unchanged.
     */
    bool Lookup(const std::string& receipt, std::string& job, int64_t& atoms) const;

private:
    std::map<std::string, SwarmWorkReceipt> m_receipts;
    int64_t m_total{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WORKPAY_RECEIPT_H
