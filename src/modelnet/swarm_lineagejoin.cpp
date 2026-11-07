// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_lineagejoin.h>

namespace modelnet {

// A local join can record an artifact lineage. A checkpoint-only claim is not trust.
SwarmLineageJoinResult SwarmJoinLineageLocal(const SwarmLineageJoin& join, std::string& err)
{
    SwarmLineageJoinResult result;
    result.trusted = false;
    result.joined = false;

    if (join.lineage_id.empty()) {
        result.code = "LINEAGE";
        result.trusted = false;
        result.joined = false;
        err = "LINEAGE";
        return result;
    }
    if (join.checkpoint_only) {
        result.code = "NOT_TRUST";
        result.trusted = false;
        result.joined = false;
        err = "NOT_TRUST";
        return result;
    }
    if (!join.artifact) {
        result.code = "ARTIFACT";
        result.trusted = false;
        result.joined = false;
        err = "ARTIFACT";
        return result;
    }
    if (join.want_trust) {
        result.code = "HELD";
        result.trusted = false;
        result.joined = true;
        err = "HELD";
        return result;
    }

    result.code = "NOTED";
    result.trusted = false;
    result.joined = true;
    err.clear();
    return result;
}

} // namespace modelnet
