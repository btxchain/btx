// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_receiptbind.h>

#include <string>
#include <utility>

namespace modelnet {

bool SwarmReceiptBind::Bind(const std::string& receipt, const std::string& job, int64_t atoms, std::string& err)
{
    if (receipt.empty() || job.empty()) {
        err = "RECEIPT";
        return false;
    }
    if (atoms < 1) {
        err = "ATOMS";
        return false;
    }
    if (m_rows.find(receipt) != m_rows.end()) {
        err = "REPLAY";
        return false;
    }
    Row row;
    row.job = job;
    row.atoms = atoms;
    m_rows.emplace(receipt, std::move(row));
    m_total += atoms;
    err.clear();
    return true;
}

int64_t SwarmReceiptBind::total() const
{
    return m_total;
}

bool SwarmReceiptBind::Has(const std::string& receipt) const
{
    return m_rows.find(receipt) != m_rows.end();
}

} // namespace modelnet
