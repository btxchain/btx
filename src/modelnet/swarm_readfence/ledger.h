// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_LEDGER_H
#define BITCOIN_MODELNET_SWARM_READFENCE_LEDGER_H

#include <cstddef>
#include <set>
#include <string>
#include <utility>

namespace modelnet {

/**
 * Recorded reads of placed pages.
 * Record stores one (member, page) pair.
 * An empty member or an empty page is refused.
 * A second record of the same pair stays one record.
 * Recording a read moves no bytes.
 */
class SwarmReadLedger {
public:
    bool recorded(const std::string& member, const std::string& page) const;
    std::size_t size() const;

    bool Record(const std::string& member, const std::string& page);

private:
    std::set<std::pair<std::string, std::string>> m_reads;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_LEDGER_H
