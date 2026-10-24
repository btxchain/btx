// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGPUOFF_H
#define BTX_MODELNET_SWARM_NOTNOGPUOFF_H

#include <string>

namespace modelnet {

/**
 * A local note about GPU training on one device. device_json is true when
 * a device.json is present. want_train asks this note to train on a GPU.
 *
 * Without device.json, GPU training stays off. training and gpu stay false
 * on every path.
 */
struct SwarmNotNoGpuOff {
    std::string device_id;
    bool device_json{false};
    bool want_train{false};
};

/**
 * Outcome of noting GPU training. training and gpu stay false on every
 * path. Without device.json, GPU training stays off.
 */
struct SwarmNotNoGpuOffResult {
    std::string code;
    bool training{false};
    bool gpu{false};
};

/**
 * Note GPU training without starting it.
 * Order, first match wins: an empty device_id is DEVICE. If device_json
 * is false, the note is NOT_RUN even when want_train is false. want_train
 * is NOT_RUN. Otherwise the note is NOTED and err is cleared. training
 * and gpu stay false on every path. Without device.json, GPU training
 * stays off.
 */
SwarmNotNoGpuOffResult SwarmNoteNotNoGpuOff(const SwarmNotNoGpuOff& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGPUOFF_H
