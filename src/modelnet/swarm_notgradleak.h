// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTGRADLEAK_H
#define BTX_MODELNET_SWARM_NOTGRADLEAK_H

#include <string>

namespace modelnet {

/**
 * A local note about one gradient. want_publish asks this note to publish it.
 *
 * This note does not publish a gradient or move bytes.
 * published and bytes_moved stay false on every path.
 */
struct SwarmNotGradLeak {
    std::string gradient_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a gradient-publish request.
 * published and bytes_moved stay false on every path: this note does not
 * publish a gradient or move bytes.
 */
struct SwarmNotGradLeakResult {
    std::string code;
    bool published{false};
    bool bytes_moved{false};
};

/**
 * Note a gradient-publish request without publishing a gradient or moving bytes.
 * Order, first match wins: an empty gradient_id is GRADIENT.
 * want_publish is HELD.
 * Otherwise the note is NOTED and err is clear.
 * published and bytes_moved stay false on every path.
 */
SwarmNotGradLeakResult SwarmNoteNotGradLeak(const SwarmNotGradLeak& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTGRADLEAK_H
