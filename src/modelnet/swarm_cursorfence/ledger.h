// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_LEDGER_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_LEDGER_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * First hash stored for each step.
 * StoreFirst keeps the first non-empty hash and refuses every later one.
 * An empty hash is refused and leaves the step unchanged.
 * There is no method that mines or moves bytes.
 */
class SwarmCursorFenceLedger {
public:
    bool stored(int64_t step) const;
    std::string hash_at(int64_t step) const;

    /**
     * Store hash for step when that step has none.
     * An empty hash is refused. A step that already has a hash is refused.
     * On refusal the stored hash stays.
     */
    bool StoreFirst(int64_t step, const std::string& hash);

private:
    std::map<int64_t, std::string> m_hashes;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_LEDGER_H
