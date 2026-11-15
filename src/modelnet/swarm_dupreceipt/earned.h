// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_EARNED_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_EARNED_H

#include <cstdint>
#include <set>
#include <string>

namespace modelnet {

/**
 * In-memory earned counter.
 * add() credits one receipt once. A receipt already credited is refused
 * and the counter stays. This counter is not broadcast.
 */
class SwarmDupEarned {
public:
    bool add(const std::string& receipt, int64_t atoms);
    int64_t total() const;
    bool paid(const std::string& receipt) const;

private:
    std::set<std::string> m_paid;
    int64_t m_total{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_EARNED_H
