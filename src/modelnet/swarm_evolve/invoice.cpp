// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/invoice.h>

#include <modelnet/swarm_paymesh.h>

#include <limits>

namespace modelnet {

bool SwarmEvolveInvoice::Record(int64_t atoms, std::string& err)
{
    if (atoms <= 0 || m_earned > std::numeric_limits<int64_t>::max() - atoms) {
        err = "INVOICE";
        return false;
    }
    if (SwarmSchedulerHasSpendKey()) {
        err = "INVOICE";
        return false;
    }

    SwarmEvolveInvoiceRecord record;
    record.atoms = atoms;
    record.automatic_spend = kSwarmAutomaticSpendAtoms;
    record.broadcast = false;
    m_records.push_back(record);
    m_earned += atoms;
    m_automatic_spend = kSwarmAutomaticSpendAtoms;
    err.clear();
    return true;
}

} // namespace modelnet
