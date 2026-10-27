// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOABLATE_H
#define BTX_MODELNET_SWARM_NOTNOABLATE_H

#include <string>

namespace modelnet {

struct SwarmNotNoAblate {
    std::string run_id;
    bool want_change{false};
};

struct SwarmNotNoAblateResult {
    std::string code;
    bool changed{false};
    bool trained{false};
};

/** Record a note only. An ablation note does not change weights. */
SwarmNotNoAblateResult SwarmNoteNotNoAblate(const SwarmNotNoAblate& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOABLATE_H
