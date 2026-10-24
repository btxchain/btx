// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CYCLEPARENT_H
#define BTX_MODELNET_SWARM_CYCLEPARENT_H

#include <string>

namespace modelnet {

struct SwarmCycleParent {
    std::string parent_id;
    std::string candidate_id;
    bool qualified{false};
    bool want_advance{false};
};

struct SwarmCycleParentResult {
    std::string code;
    bool advanced{false};
    std::string parent_id;
};

/** A qualified candidate can be recorded as the next parent. An unqualified candidate leaves the parent in place. This record does not train. */
SwarmCycleParentResult SwarmAdvanceParent(const SwarmCycleParent& cycle, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CYCLEPARENT_H
