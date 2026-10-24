// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYCYCLE_TRANSFER_H
#define BITCOIN_MODELNET_SWARM_PAYCYCLE_TRANSFER_H

#include <cstdint>
#include <set>
#include <string>

namespace modelnet {

class SwarmPayPools;

/**
 * In-memory batch transfers. A committed payment id cannot be applied again.
 * A refusal commits nothing and does not consume the payment id.
 * Sequence advances by one on success. No L1 transaction is built.
 */
class SwarmPayTransfer {
public:
    bool Apply(SwarmPayPools& pools, const std::string& from_pool, const std::string& to_pool,
               const std::string& payment_id, int64_t atoms, std::string& err);
    int64_t sequence() const;

private:
    std::set<std::string> m_ids;
    int64_t m_sequence{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYCYCLE_TRANSFER_H
