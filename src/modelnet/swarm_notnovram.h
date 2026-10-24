// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOVRAM_H
#define BTX_MODELNET_SWARM_NOTNOVRAM_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one device. vram_mib is a caller-supplied figure,
 * not a measurement. want_claim asks this note to claim VRAM.
 *
 * A missing device file claims no VRAM. claimed stays false and mib
 * stays 0 on every path.
 */
struct SwarmNotNoVram {
    std::string device_id;
    int64_t vram_mib{0};
    bool want_claim{false};
};

/** Outcome of noting a VRAM claim. claimed stays false and mib stays 0. */
struct SwarmNotNoVramResult {
    std::string code;
    bool claimed{false};
    int64_t mib{0};
};

/**
 * Note a VRAM claim without reading a device file or claiming VRAM.
 * Order, first match wins:
 * 1. An empty device_id is DEVICE. claimed stays false, mib stays 0,
 *    and err is DEVICE.
 * 2. If vram_mib is not exactly 0, the note is UNMEASURED even when
 *    want_claim is false. claimed stays false, mib stays 0, and err
 *    is UNMEASURED.
 * 3. want_claim is UNMEASURED. claimed stays false, mib stays 0, and
 *    err is UNMEASURED.
 * 4. Otherwise the note is NOTED and err is cleared. claimed stays
 *    false and mib stays 0.
 * A missing device file claims no VRAM.
 */
SwarmNotNoVramResult SwarmNoteNotNoVram(const SwarmNotNoVram& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOVRAM_H
