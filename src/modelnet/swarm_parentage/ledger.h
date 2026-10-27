// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_LEDGER_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_LEDGER_H

#include <modelnet/swarm_parentage/record.h>

#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory parentage keyed by checkpoint id.
 * A checkpoint enters the map only when Bind stores a complete row.
 * A second bind keeps the first row. A refusal leaves the map unchanged.
 * Rows carry parent, recipe, dataset, and license. They do not carry trust.
 */
class SwarmParentageLedger {
public:
    /**
     * Store parent, recipe, dataset, and license for checkpoint.
     * Any empty argument is LINEAGE and stores nothing.
     * The same four fields again are REPLAY and keep the first row.
     * Any different field is CONFLICT and keeps the first row.
     * A new checkpoint stores the four fields and returns true.
     */
    bool Bind(const std::string& checkpoint,
              const std::string& parent,
              const std::string& recipe,
              const std::string& dataset,
              const std::string& license,
              std::string& err);

    /** True when Bind has stored this checkpoint. */
    bool bound(const std::string& checkpoint) const;

    /** Stored parent, or empty when the checkpoint is absent. */
    std::string parent_of(const std::string& checkpoint) const;

    /** Stored recipe, or empty when the checkpoint is absent. */
    std::string recipe_of(const std::string& checkpoint) const;

    /** Stored dataset, or empty when the checkpoint is absent. */
    std::string dataset_of(const std::string& checkpoint) const;

    /** Stored license, or empty when the checkpoint is absent. */
    std::string license_of(const std::string& checkpoint) const;

private:
    const SwarmParentageBinding* Find(const std::string& checkpoint) const;

    std::map<std::string, SwarmParentageBinding> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_LEDGER_H
