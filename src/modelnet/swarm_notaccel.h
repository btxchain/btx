// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTACCEL_H
#define BTX_MODELNET_SWARM_NOTACCEL_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. gpu_present records whether a GPU is on the
 * platform. want_train asks this note to advertise training.
 *
 * A platform must not advertise training it does not have. want_train is
 * refused even when gpu_present is true, because no training job is started
 * here. advertised stays false and training stays false on every path.
 */
struct SwarmNotAccel {
    std::string node_id;
    bool gpu_present{false};
    bool want_train{false};
};

/**
 * Outcome of noting an accelerator claim. advertised stays false and
 * training stays false on every path.
 */
struct SwarmNotAccelResult {
    std::string code;
    bool advertised{false};
    bool training{false};
};

/**
 * Note an accelerator claim without advertising or starting training.
 * Order, first match wins:
 * 1. An empty node_id is NODE. advertised stays false, training stays false,
 *    and err is NODE.
 * 2. If gpu_present is false or want_train is true, the note is CPU_ONLY.
 *    advertised stays false, training stays false, and err is CPU_ONLY.
 *    want_train is refused even when gpu_present is true, because no training
 *    job is started here.
 * 3. Otherwise the note is NOTED. advertised stays false, training stays
 *    false, and err is cleared.
 * A platform must not advertise training it does not have.
 */
SwarmNotAccelResult SwarmNoteNotAccel(const SwarmNotAccel& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTACCEL_H
