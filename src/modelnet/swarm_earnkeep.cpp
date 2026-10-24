// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earnkeep.h>

namespace modelnet {

SwarmEarnKeepResult SwarmKeepEarned(const SwarmEarnKeep& row, std::string& err)
{
    // An earned row stays when the coordinator is gone and is not spent.
    SwarmEarnKeepResult result;
    result.dropped = false;
    result.spent = false;
    if (row.row_id.empty()) {
        result.code = "ROW";
        result.dropped = false;
        result.spent = false;
        result.atoms = 0;
        err = "ROW";
        return result;
    }
    if (row.atoms < 0) {
        result.code = "RANGE";
        result.dropped = false;
        result.spent = false;
        result.atoms = 0;
        err = "RANGE";
        return result;
    }
    if (row.coordinator_gone) {
        result.code = "STAYS";
        result.dropped = false;
        result.spent = false;
        result.atoms = row.atoms;
        err = "STAYS";
        return result;
    }
    if (row.want_drop || row.want_spend) {
        result.code = "HELD";
        result.dropped = false;
        result.spent = false;
        result.atoms = row.atoms;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.dropped = false;
    result.spent = false;
    result.atoms = row.atoms;
    err.clear();
    return result;
}

} // namespace modelnet
