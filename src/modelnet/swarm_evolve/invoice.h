// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVOLVE_INVOICE_H
#define BITCOIN_MODELNET_SWARM_EVOLVE_INVOICE_H

#include <modelnet/swarm_frontier.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** One local invoice row. automatic_spend stays "0". broadcast stays false. */
struct SwarmEvolveInvoiceRecord {
    int64_t atoms{0};
    std::string automatic_spend{kSwarmAutomaticSpendAtoms};
    bool broadcast{false};
};

/**
 * Invoice ledger owned by the generation driver.
 * Record adds atoms to the earned counter inside this object.
 * It does not broadcast and does not change automatic spend.
 */
class SwarmEvolveInvoice {
public:
    bool Record(int64_t atoms, std::string& err);

    int64_t Earned() const { return m_earned; }
    const std::string& AutomaticSpend() const { return m_automatic_spend; }
    bool Broadcast() const { return false; }
    const std::vector<SwarmEvolveInvoiceRecord>& Records() const { return m_records; }

private:
    int64_t m_earned{0};
    std::string m_automatic_spend{kSwarmAutomaticSpendAtoms};
    std::vector<SwarmEvolveInvoiceRecord> m_records;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVOLVE_INVOICE_H
