// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/book.h>

#include <modelnet/swarm_dupreceipt/atoms.h>

#include <utility>

namespace modelnet {

bool SwarmDupReceiptBook::contains(const std::string& receipt) const
{
    if (receipt.empty()) {
        return false;
    }
    return m_rows.find(receipt) != m_rows.end();
}

bool SwarmDupReceiptBook::paid(const std::string& receipt) const
{
    const auto found = m_rows.find(receipt);
    if (found == m_rows.end()) {
        return false;
    }
    return found->second.paid;
}

int64_t SwarmDupReceiptBook::paid_atoms(const std::string& receipt) const
{
    const auto found = m_rows.find(receipt);
    if (found == m_rows.end() || !found->second.paid) {
        return 0;
    }
    return found->second.atoms;
}

int64_t SwarmDupReceiptBook::earned() const
{
    return m_earned.total();
}

std::size_t SwarmDupReceiptBook::size() const
{
    return m_rows.size();
}

bool SwarmDupReceiptBook::store(const std::string& receipt)
{
    if (contains(receipt)) {
        return false;
    }
    SwarmDupReceiptRow row = SwarmDupMakeRow(receipt);
    if (!SwarmDupRowBound(row)) {
        return false;
    }
    m_rows.emplace(receipt, std::move(row));
    return true;
}

bool SwarmDupReceiptBook::credit(const std::string& receipt, int64_t atoms, bool research_key, bool scheduler)
{
    const auto found = m_rows.find(receipt);
    if (found == m_rows.end()) {
        return false;
    }
    if (atoms < 1 || found->second.paid) {
        return false;
    }
    if (research_key || scheduler) {
        return false;
    }
    if (!SwarmDupAtoms{}.fits(m_earned.total(), atoms)) {
        return false;
    }
    SwarmDupReceiptRow& row = found->second;
    const int64_t kept = row.atoms;
    row.paid = true;
    row.atoms = atoms;
    if (!m_earned.add(receipt, atoms)) {
        row.paid = false;
        row.atoms = kept;
        return false;
    }
    return true;
}

} // namespace modelnet
