// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/record.h>

#include <modelnet/swarm_parentage/codes.h>
#include <modelnet/swarm_parentage/limits.h>

#include <string>

namespace modelnet {

bool SwarmParentageArgumentsPresent(const std::string& checkpoint,
                                    const std::string& parent,
                                    const std::string& recipe,
                                    const std::string& dataset,
                                    const std::string& license,
                                    std::string& err)
{
    // An empty parent is LINEAGE. It is not stored as a baseline head.
    if (checkpoint.empty() || parent.empty() || recipe.empty() || dataset.empty() || license.empty()) {
        err = SWARM_PARENTAGE_LINEAGE;
        return false;
    }
    return true;
}

bool SwarmParentageBindingComplete(const SwarmParentageBinding& row)
{
    const int present = (row.parent.empty() ? 0 : 1) + (row.recipe.empty() ? 0 : 1) +
                        (row.dataset.empty() ? 0 : 1) + (row.license.empty() ? 0 : 1);
    return present == kSwarmParentageFieldCount;
}

int SwarmParentageFieldMismatches(const SwarmParentageBinding& row,
                                  const std::string& parent,
                                  const std::string& recipe,
                                  const std::string& dataset,
                                  const std::string& license)
{
    int mismatches = 0;
    if (row.parent != parent) {
        ++mismatches;
    }
    if (row.recipe != recipe) {
        ++mismatches;
    }
    if (row.dataset != dataset) {
        ++mismatches;
    }
    if (row.license != license) {
        ++mismatches;
    }
    return mismatches;
}

SwarmParentageBinding SwarmParentageMakeBinding(const std::string& parent,
                                                const std::string& recipe,
                                                const std::string& dataset,
                                                const std::string& license)
{
    SwarmParentageBinding row;
    row.parent = parent;
    row.recipe = recipe;
    row.dataset = dataset;
    row.license = license;
    return row;
}

} // namespace modelnet
