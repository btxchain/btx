// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RECEIPTBIND_H
#define BTX_MODELNET_SWARM_RECEIPTBIND_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Binds one receipt to a job and an atom count.
 *
 * Atoms are an accounting integer. A successful bind adds them to the
 * running total. They are not spent. A duplicate receipt does not pay
 * twice: the first row stays and the total does not increase again.
 *
 * Bind order, first match wins: an empty receipt or job is RECEIPT and
 * stores nothing. atoms < 1 is ATOMS and stores nothing. A receipt that
 * is already stored is REPLAY and does not add atoms again. Otherwise
 * the receipt and job are stored, atoms are added to the total, err is
 * cleared, and Bind returns true.
 *
 * This ledger does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or address.
 */
class SwarmReceiptBind {
public:
    bool Bind(const std::string& receipt, const std::string& job, int64_t atoms, std::string& err);
    int64_t total() const;
    bool Has(const std::string& receipt) const;

private:
    struct Row {
        std::string job;
        int64_t atoms{0};
    };

    std::map<std::string, Row> m_rows;
    int64_t m_total{0};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_RECEIPTBIND_H
