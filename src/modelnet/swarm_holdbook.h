// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_HOLDBOOK_H
#define BTX_MODELNET_SWARM_HOLDBOOK_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmHoldBook {
    std::string holdout_id;
    int64_t members{0};
    int64_t index{0};
    bool want_rotate{false};
    bool want_score{false};
};

struct SwarmHoldBookResult {
    std::string code;
    bool rotated{false};
    bool scored{false};
    int64_t index{0};
    int64_t members{0};
};

/** A fixed holdout can be indexed and cannot rotate or publish a score. */
SwarmHoldBookResult SwarmUseHoldout(const SwarmHoldBook& book, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_HOLDBOOK_H
