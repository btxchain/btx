// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/invoice_path.h>

#include <modelnet/swarm_paystage/preimage.h>

namespace modelnet {

bool SwarmPayInvoicePath::Reveal(const SwarmPaySettle& request, int64_t& out_atoms, std::string& err)
{
    out_atoms = 0;
    if (request.preimage.size() != 32) {
        err = "PREIMAGE";
        return false;
    }
    if (request.invoice_id.empty() || request.beneficiary.empty() || request.objective.empty() || request.atoms < 1) {
        err = "INVOICE";
        return false;
    }
    if (request.liquidity_id.empty()) {
        err = "LIQUIDITY";
        return false;
    }
    if (!m_open) {
        if (!m_book.Open(err)) {
            return false;
        }
        m_open = true;
    }
    const uint256 hashlock = SwarmPayPreimageHash(request.preimage);
    if (!m_book.Create(request.invoice_id, request.beneficiary, request.objective, request.atoms, hashlock, err)) {
        return false;
    }
    if (!m_book.Reserve(request.invoice_id, request.liquidity_id, err)) {
        return false;
    }
    if (!m_book.Reveal(request.invoice_id, request.preimage, err)) {
        return false;
    }
    out_atoms = request.atoms;
    err.clear();
    return true;
}

bool SwarmPayInvoicePath::MultiHopQualified() const
{
    return m_book.MultiHopQualified();
}

} // namespace modelnet
