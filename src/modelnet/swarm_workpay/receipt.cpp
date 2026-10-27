// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workpay/receipt.h>

#include <modelnet/swarm_workpay/codes.h>

#include <limits>

namespace modelnet {
namespace {

bool Fits(int64_t have, int64_t atoms)
{
    if (atoms < 1 || have < 0) {
        return false;
    }
    // have + atoms would exceed int64 max.
    return have <= std::numeric_limits<int64_t>::max() - atoms;
}

} // namespace

bool SwarmWorkReceiptBook::Bind(const std::string& receipt, const std::string& job, int64_t atoms, std::string& err)
{
    if (receipt.empty() || job.empty()) {
        err = SWARM_WORK_RECEIPT;
        return false;
    }
    if (atoms < 1) {
        err = SWARM_WORK_ATOMS;
        return false;
    }
    if (m_receipts.count(receipt) != 0) {
        err = SWARM_WORK_REPLAY;
        return false;
    }
    if (!Fits(m_total, atoms)) {
        err = SWARM_WORK_ATOMS;
        return false;
    }
    SwarmWorkReceipt row;
    row.job = job;
    row.atoms = atoms;
    m_receipts.emplace(receipt, std::move(row));
    m_total += atoms;
    err.clear();
    return true;
}

int64_t SwarmWorkReceiptBook::total() const
{
    return m_total;
}

bool SwarmWorkReceiptBook::bound(const std::string& receipt) const
{
    return m_receipts.count(receipt) != 0;
}

bool SwarmWorkReceiptBook::Find(const std::string& receipt, int64_t& atoms) const
{
    const auto it = m_receipts.find(receipt);
    if (it == m_receipts.end()) {
        return false;
    }
    atoms = it->second.atoms;
    return true;
}

bool SwarmWorkReceiptBook::Lookup(const std::string& receipt, std::string& job, int64_t& atoms) const
{
    const auto it = m_receipts.find(receipt);
    if (it == m_receipts.end()) {
        return false;
    }
    job = it->second.job;
    atoms = it->second.atoms;
    return true;
}

} // namespace modelnet
