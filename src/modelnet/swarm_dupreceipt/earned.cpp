// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/earned.h>

#include <modelnet/swarm_dupreceipt/atoms.h>

namespace modelnet {

bool SwarmDupEarned::add(const std::string& receipt, int64_t atoms)
{
    if (receipt.empty()) {
        return false;
    }
    if (m_paid.find(receipt) != m_paid.end()) {
        return false;
    }
    if (!SwarmDupAtoms{}.fits(m_total, atoms)) {
        return false;
    }
    m_paid.insert(receipt);
    m_total += atoms;
    return true;
}

int64_t SwarmDupEarned::total() const
{
    return m_total;
}

bool SwarmDupEarned::paid(const std::string& receipt) const
{
    return m_paid.find(receipt) != m_paid.end();
}

} // namespace modelnet
