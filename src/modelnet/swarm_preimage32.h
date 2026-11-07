// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PREIMAGE32_H
#define BTX_MODELNET_SWARM_PREIMAGE32_H

#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Local record of invoices claimed with a 32-byte preimage.
 *
 * Claim order, first match wins: an empty invoice is INVOICE and stores
 * nothing. A preimage whose size is not 32 is PREIMAGE and stores nothing.
 * An invoice that is already stored is REPLAY and is not stored again.
 * Otherwise the invoice is stored, err is cleared, and Claim returns true.
 *
 * A preimage whose size is not 32 claims nothing. This record does not
 * broadcast, spend, spawn a child process, open a network connection, or
 * record a hostname or address.
 */
class SwarmPreimage32 {
public:
    bool Claim(const std::string& invoice, const std::vector<unsigned char>& preimage, std::string& err);
    bool Claimed(const std::string& invoice) const;

private:
    std::set<std::string> m_invoices;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PREIMAGE32_H
