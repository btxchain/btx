// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WORKPAY_EARNED_H
#define BITCOIN_MODELNET_SWARM_WORKPAY_EARNED_H

#include <cstdint>
#include <set>
#include <string>

namespace modelnet {

/**
 * In-memory earned counter. Credit adds the bound atoms of one receipt
 * once. A second credit of that receipt does not add again.
 * This counter is not broadcast.
 */
class SwarmWorkEarned {
public:
    /**
     * An empty receipt is RECEIPT and adds nothing.
     * atoms below 1 is ATOMS and adds nothing.
     * A receipt already credited is REPLAY and adds nothing.
     * A sum that would pass int64 max is ATOMS and adds nothing.
     * Otherwise atoms are added to earned and the receipt is paid.
     */
    bool Credit(const std::string& receipt, int64_t atoms, std::string& err);

    /** Atoms added by successful credits. */
    int64_t earned() const;

    /** True when this receipt has already been credited. */
    bool paid(const std::string& receipt) const;

private:
    std::set<std::string> m_paid;
    int64_t m_earned{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WORKPAY_EARNED_H
