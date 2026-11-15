// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_VRAM_H
#define BTX_MODELNET_SWARM_VRAM_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of video memory for one node. node_id names the note.
 * vram_mib is the reported video memory in MiB. license_allows_training
 * marks a training grant. want_train asks this note to train.
 *
 * training stays false on every path. Nothing is launched. No hostnames
 * or IPs are used.
 */
struct SwarmVramTrain {
    std::string node_id;
    int64_t vram_mib{0};
    bool license_allows_training{false};
    bool want_train{false};
};

/**
 * Outcome of noting video memory. training stays false: this note does
 * not start training. Nothing is launched.
 */
struct SwarmVramTrainResult {
    bool training{false};
    std::string code;
};

/**
 * Note video memory without starting training. Order, first match wins:
 * an empty node_id or vram_mib below 0 is VRAM. training stays false
 * and err is VRAM.
 * want_train with vram_mib == 0 or without license_allows_training is
 * CPU_ONLY. training stays false and err is CPU_ONLY. Zero VRAM or a
 * missing training grant is not a trainer. This wins even when the
 * other of those two is true.
 * want_train is HELD. training stays false and err is cleared. This
 * note does not start training even when VRAM and a license are present.
 * Otherwise the note is NOTED. training stays false and err is cleared.
 * Nothing is launched. No hostnames or IPs are used.
 */
SwarmVramTrainResult SwarmNoteVramTrain(const SwarmVramTrain& train, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_VRAM_H
