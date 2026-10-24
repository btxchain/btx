// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTVRAMZERO_H
#define BTX_MODELNET_SWARM_NOTVRAMZERO_H

#include <string>

namespace modelnet {

/**
 * A local note about VRAM on one node. vram_mib is the reported memory
 * in MiB. want_train asks this note to train.
 *
 * The default without device.json reports no VRAM and trains nothing
 * from this note. training stays false and applied_vram stays 0 on
 * every path.
 */
struct SwarmNotVramZero {
    std::string node_id;
    int vram_mib{0};
    bool want_train{false};
};

/**
 * Outcome of noting a VRAM claim. training stays false and applied_vram
 * stays 0 on every path.
 */
struct SwarmNotVramZeroResult {
    std::string code;
    bool training{false};
    int applied_vram{0};
};

/**
 * Note a VRAM claim without applying VRAM or starting training.
 * Order, first match wins:
 * 1. An empty node_id is NODE. training stays false, applied_vram stays 0,
 *    and err is NODE.
 * 2. If vram_mib is not exactly 0, the note is CPU_ONLY even when
 *    want_train is false. training stays false, applied_vram stays 0,
 *    and err is CPU_ONLY.
 * 3. want_train is CPU_ONLY. training stays false, applied_vram stays 0,
 *    and err is CPU_ONLY.
 * 4. Otherwise the note is NOTED and err is cleared. training stays false
 *    and applied_vram stays 0.
 * The default without device.json reports no VRAM and trains nothing
 * from this note.
 */
SwarmNotVramZeroResult SwarmNoteNotVramZero(const SwarmNotVramZero& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTVRAMZERO_H
