// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LINEAGEJOIN_H
#define BTX_MODELNET_SWARM_LINEAGEJOIN_H

#include <string>

namespace modelnet {

/** A local join can record an artifact lineage. A checkpoint-only claim is not trust. */
struct SwarmLineageJoin {
    std::string lineage_id;
    bool checkpoint_only{false};
    bool artifact{false};
    bool want_trust{false};
};

struct SwarmLineageJoinResult {
    std::string code;
    bool trusted{false};
    bool joined{false};
};

/** A local join can record an artifact lineage. A checkpoint-only claim is not trust. */
SwarmLineageJoinResult SwarmJoinLineageLocal(const SwarmLineageJoin& join, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LINEAGEJOIN_H
