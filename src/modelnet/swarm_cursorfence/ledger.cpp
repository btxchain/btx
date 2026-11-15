// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/ledger.h>

namespace modelnet {

bool SwarmCursorFenceLedger::stored(int64_t step) const
{
    return m_hashes.find(step) != m_hashes.end();
}

std::string SwarmCursorFenceLedger::hash_at(int64_t step) const
{
    const auto it = m_hashes.find(step);
    if (it == m_hashes.end()) return {};
    return it->second;
}

bool SwarmCursorFenceLedger::StoreFirst(int64_t step, const std::string& hash)
{
    if (hash.empty()) return false;
    if (m_hashes.find(step) != m_hashes.end()) return false;
    m_hashes.emplace(step, hash);
    return true;
}

} // namespace modelnet
