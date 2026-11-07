// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/transfer.h>

#include <modelnet/swarm_paycycle/codes.h>
#include <modelnet/swarm_paycycle/pools.h>

#include <cstdint>
#include <set>
#include <string>

namespace modelnet {

bool SwarmPayTransfer::Apply(SwarmPayPools& pools, const std::string& from_pool, const std::string& to_pool,
                             const std::string& payment_id, int64_t atoms, std::string& err)
{
    if (!pools.funded(from_pool) || !pools.funded(to_pool)) {
        err = SWARM_PAYCYCLE_FUNDING;
        return false;
    }
    if (atoms < 1) {
        err = SWARM_PAYCYCLE_AMOUNT;
        return false;
    }
    if (m_ids.find(payment_id) != m_ids.end()) {
        err = SWARM_PAYCYCLE_REPLAY;
        return false;
    }
    if (!pools.Move(from_pool, to_pool, atoms, err)) {
        return false;
    }
    m_ids.insert(payment_id);
    ++m_sequence;
    err.clear();
    return true;
}

int64_t SwarmPayTransfer::sequence() const
{
    return m_sequence;
}

} // namespace modelnet
