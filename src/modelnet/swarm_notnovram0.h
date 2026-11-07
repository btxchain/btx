// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOVRAM0_H
#define BTX_MODELNET_SWARM_NOTNOVRAM0_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about VRAM on one node. no_device records that no device
 * file is present. want_vram asks this note to grant VRAM.
 *
 * Without a device file VRAM stays zero. granted stays false and bytes
 * stays 0 on every path.
 */
struct SwarmNotNoVram0 {
    std::string node_id;
    bool no_device{false};
    bool want_vram{false};
};

/**
 * Outcome of noting a VRAM request. granted stays false and bytes stays
 * 0 on every path. Without a device file VRAM stays zero.
 */
struct SwarmNotNoVram0Result {
    std::string code;
    bool granted{false};
    int64_t bytes{0};
};

/**
 * Note a VRAM request without reading a device file or granting VRAM.
 * Order, first match wins: an empty node_id is NODE. If no_device is
 * true, the note is ZERO even when want_vram is false. want_vram is
 * ZERO. Otherwise the note is NOTED and err is cleared. granted stays
 * false and bytes stays 0 on every path. Without a device file VRAM
 * stays zero.
 */
SwarmNotNoVram0Result SwarmNoteNotNoVram0(const SwarmNotNoVram0& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOVRAM0_H
