// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSEEDCPU_H
#define BTX_MODELNET_SWARM_NOTNOSEEDCPU_H

#include <string>

namespace modelnet {

/**
 * A local note about seeding and CPU evaluation on one node. no_device
 * records that no device file is present. want_train asks this note to
 * train on a GPU.
 *
 * Without a device file the node seeds and evaluates on CPU and does not
 * train on a GPU. trained and gpu stay false on every path.
 */
struct SwarmNotNoSeedCpu {
    std::string node_id;
    bool no_device{false};
    bool want_train{false};
};

/**
 * Outcome of noting a no-device CPU seed. trained and gpu stay false on
 * every path. Without a device file the node seeds and evaluates on CPU
 * and does not train on a GPU.
 */
struct SwarmNotNoSeedCpuResult {
    std::string code;
    bool trained{false};
    bool gpu{false};
};

/**
 * Note a no-device CPU seed without training on a GPU.
 * Order, first match wins: an empty node_id is NODE. If no_device is
 * true, the note is CPU_ONLY even when want_train is false. want_train
 * is OFF. Otherwise the note is NOTED and err is cleared. trained and
 * gpu stay false on every path. Without a device file the node seeds
 * and evaluates on CPU and does not train on a GPU.
 */
SwarmNotNoSeedCpuResult SwarmNoteNotNoSeedCpu(const SwarmNotNoSeedCpu& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSEEDCPU_H
