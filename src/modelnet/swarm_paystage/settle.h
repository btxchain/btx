// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYSTAGE_SETTLE_H
#define BTX_MODELNET_SWARM_PAYSTAGE_SETTLE_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One invoice settle. The preimage is revealed to SwarmInvoiceBook.
 * research_key or scheduler refuses the settle before any bucket moves.
 * A hashlock is not a qualified multi-hop network.
 */
struct SwarmPaySettle {
    std::string invoice_id;
    std::string beneficiary;
    std::string objective;
    std::string liquidity_id;
    int64_t atoms{0};
    std::vector<unsigned char> preimage;
    bool research_key{false};
    bool scheduler{false};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYSTAGE_SETTLE_H
