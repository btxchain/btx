// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYSTAGE_INVOICE_PATH_H
#define BTX_MODELNET_SWARM_PAYSTAGE_INVOICE_PATH_H

#include <modelnet/swarm_invoice.h>
#include <modelnet/swarm_paystage/settle.h>

#include <string>

namespace modelnet {

/**
 * Open, Create, Reserve, and Reveal on one SwarmInvoiceBook.
 * A matching reveal asks the caller to credit earned only.
 * This path does not credit escrow, collateral, or fees.
 */
class SwarmPayInvoicePath {
public:
    /**
     * On success, out_atoms is the invoice atoms and err is clear.
     * The book is opened on the first call and left open.
     * A preimage whose size is not 32 is PREIMAGE and out_atoms stays 0.
     * This function does not credit a bucket.
     */
    bool Reveal(const SwarmPaySettle& request, int64_t& out_atoms, std::string& err);

    /** SwarmInvoiceBook::MultiHopQualified. This stays false. */
    bool MultiHopQualified() const;

private:
    SwarmInvoiceBook m_book;
    bool m_open{false};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYSTAGE_INVOICE_PATH_H
