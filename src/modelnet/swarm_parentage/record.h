// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_RECORD_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_RECORD_H

#include <string>

namespace modelnet {

/**
 * Parentage stored for one checkpoint.
 * The record holds a parent, a recipe, a dataset, and a license.
 * It has no trust bit, no realm-promotion bit, and no ExactReplay admission bit.
 * An empty parent is not a baseline head and is never stored.
 */
struct SwarmParentageBinding {
    std::string parent;
    std::string recipe;
    std::string dataset;
    std::string license;
};

/**
 * True when checkpoint, parent, recipe, dataset, and license are all non-empty.
 * Any empty argument sets err to LINEAGE.
 * A present set of arguments leaves err unchanged.
 */
bool SwarmParentageArgumentsPresent(const std::string& checkpoint,
                                    const std::string& parent,
                                    const std::string& recipe,
                                    const std::string& dataset,
                                    const std::string& license,
                                    std::string& err);

/** True when every stored field is non-empty. */
bool SwarmParentageBindingComplete(const SwarmParentageBinding& row);

/**
 * How many of parent, recipe, dataset, and license differ from row.
 * Zero means the four fields are the same. A positive count means at least one differs.
 */
int SwarmParentageFieldMismatches(const SwarmParentageBinding& row,
                                  const std::string& parent,
                                  const std::string& recipe,
                                  const std::string& dataset,
                                  const std::string& license);

/** Copy the four fields into a binding. The copy has no trust or admission flag. */
SwarmParentageBinding SwarmParentageMakeBinding(const std::string& parent,
                                                const std::string& recipe,
                                                const std::string& dataset,
                                                const std::string& license);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_RECORD_H
