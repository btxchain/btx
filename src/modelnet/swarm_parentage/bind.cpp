// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/bind.h>

#include <modelnet/swarm_parentage/codes.h>
#include <modelnet/swarm_parentage/record.h>

#include <string>
#include <utility>

namespace modelnet {

bool SwarmParentageDecideBind(const SwarmParentageBinding* existing,
                              const std::string& checkpoint,
                              const std::string& parent,
                              const std::string& recipe,
                              const std::string& dataset,
                              const std::string& license,
                              SwarmParentageBinding& created,
                              std::string& err)
{
    if (!SwarmParentageArgumentsPresent(checkpoint, parent, recipe, dataset, license, err)) {
        return false;
    }
    if (existing != nullptr) {
        const int mismatches = SwarmParentageFieldMismatches(*existing, parent, recipe, dataset, license);
        if (mismatches == 0) {
            err = SWARM_PARENTAGE_REPLAY;
            return false;
        }
        err = SWARM_PARENTAGE_CONFLICT;
        return false;
    }
    SwarmParentageBinding row = SwarmParentageMakeBinding(parent, recipe, dataset, license);
    if (!SwarmParentageBindingComplete(row)) {
        err = SWARM_PARENTAGE_LINEAGE;
        return false;
    }
    created = std::move(row);
    err.clear();
    return true;
}

} // namespace modelnet
