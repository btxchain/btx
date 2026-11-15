// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTGPUOFF_H
#define BTX_MODELNET_SWARM_NOTGPUOFF_H

#include <string>

namespace modelnet {

/**
 * A local note about GPU training on one node. want_train asks this note
 * to train on a GPU.
 *
 * GPU training stays off by default. This note saves no checkpoint.
 * training and checkpoint_saved stay false on every path.
 */
struct SwarmNotGpuOff {
    std::string node_id;
    bool want_train{false};
};

/**
 * Outcome of noting GPU training. training and checkpoint_saved stay
 * false on every path. GPU training stays off by default. This note
 * saves no checkpoint.
 */
struct SwarmNotGpuOffResult {
    std::string code;
    bool training{false};
    bool checkpoint_saved{false};
};

/**
 * Note GPU training without starting it or saving a checkpoint.
 * Order, first match wins: an empty node_id is NODE. want_train is
 * GPU_OFF. Otherwise the note is NOTED and err is cleared. training
 * and checkpoint_saved stay false on every path. GPU training stays
 * off by default. This note saves no checkpoint.
 */
SwarmNotGpuOffResult SwarmNoteNotGpuOff(const SwarmNotGpuOff& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTGPUOFF_H
