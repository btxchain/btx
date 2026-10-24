// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODEVICE2_H
#define BTX_MODELNET_SWARM_NOTNODEVICE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. device_file records that a device file
 * is present. want_gpu asks this note to train on a GPU.
 *
 * Without a device file the node stays CPU-only. gpu stays false and
 * vram_mib stays 0 on every path.
 */
struct SwarmNotNoDevice2 {
    std::string node_id;
    bool device_file{false};
    bool want_gpu{false};
};

/**
 * Outcome of noting a node without granting a GPU. gpu stays false and
 * vram_mib stays 0 on every path. Without a device file the node stays
 * CPU-only.
 */
struct SwarmNotNoDevice2Result {
    std::string code;
    bool gpu{false};
    int vram_mib{0};
};

/**
 * Note a node without reading a device file or starting GPU training.
 * Order, first match wins: an empty node_id is NODE. If device_file is
 * false, the note is CPU_ONLY even when want_gpu is false. want_gpu is
 * HELD. Otherwise the note is NOTED and err is cleared. gpu stays false
 * and vram_mib stays 0 on every path. Without a device file the node
 * stays CPU-only.
 */
SwarmNotNoDevice2Result SwarmNoteNotNoDevice2(const SwarmNotNoDevice2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODEVICE2_H
