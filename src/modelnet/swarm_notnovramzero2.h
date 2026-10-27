// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOVRAMZERO2_H
#define BTX_MODELNET_SWARM_NOTNOVRAMZERO2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local refusal note about one node. no_device records that no device
 * file is present. want_claim asks this note to claim VRAM.
 *
 * Without a device file, VRAM stays zero. Nothing is claimed.
 */
struct SwarmNotNoVramZero2 {
    std::string node_id;
    bool no_device{false};
    bool want_claim{false};
};

/**
 * Outcome of noting a node. claimed stays false and vram_mib stays 0 on
 * every path. Without a device file, VRAM stays zero.
 */
struct SwarmNotNoVramZero2Result {
    std::string code;
    bool claimed{false};
    int64_t vram_mib{0};
};

/**
 * Note a node without a device file. claimed stays false and vram_mib
 * stays 0 on every path.
 * Order, first match wins:
 * 1. An empty node_id is NODE. err is NODE.
 * 2. If no_device is true, the note is VRAM_ZERO even when want_claim
 *    is false. err is VRAM_ZERO.
 * 3. want_claim is HELD. err is HELD.
 * 4. Otherwise the note is NOTED and err is cleared.
 * Without a device file, VRAM stays zero.
 */
SwarmNotNoVramZero2Result SwarmNoteNotNoVramZero2(const SwarmNotNoVramZero2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOVRAMZERO2_H
