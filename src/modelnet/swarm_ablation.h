// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ABLATION_H
#define BTX_MODELNET_SWARM_ABLATION_H

#include <string>

namespace modelnet {

struct SwarmAblation {
    std::string bench_id;
    bool want_publish{false};
};

struct SwarmAblationResult {
    std::string code;
    bool published{false};
};

/**
 * An ablation publish request is held and publishes nothing.
 * Order: an empty bench_id is BENCH. want_publish true is HELD.
 * Otherwise the code is NOTED and err is cleared.
 */
SwarmAblationResult SwarmNoteAblation(const SwarmAblation& bench, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ABLATION_H
