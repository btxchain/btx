// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_preimage32.h>

#include <string>
#include <vector>

namespace modelnet {

bool SwarmPreimage32::Claim(const std::string& invoice, const std::vector<unsigned char>& preimage, std::string& err)
{
    if (invoice.empty()) {
        err = "INVOICE";
        return false;
    }
    // A preimage whose size is not 32 claims nothing.
    if (preimage.size() != 32) {
        err = "PREIMAGE";
        return false;
    }
    if (m_invoices.find(invoice) != m_invoices.end()) {
        err = "REPLAY";
        return false;
    }
    m_invoices.insert(invoice);
    err.clear();
    return true;
}

bool SwarmPreimage32::Claimed(const std::string& invoice) const
{
    return m_invoices.find(invoice) != m_invoices.end();
}

} // namespace modelnet
