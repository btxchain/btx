// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTROTATE_H
#define BTX_MODELNET_SWARM_NOTROTATE_H

#include <string>

namespace modelnet {

/**
 * A local note about a holdout. want_rotate asks this note to rotate a
 * holdout.
 *
 * This note does not rotate a holdout or reveal it, so rotated and leaked
 * stay false on every path.
 */
struct SwarmNotRotate {
    std::string suite_id;
    bool want_rotate{false};
};

/**
 * Outcome of noting a holdout rotation. rotated and leaked stay false on
 * every path.
 */
struct SwarmNotRotateResult {
    std::string code;
    bool rotated{false};
    bool leaked{false};
};

/**
 * Note that this note does not rotate a holdout or reveal it.
 * Order, first match wins: an empty suite_id is SUITE. want_rotate is
 * NOT_ROTATED. Otherwise the note is NOTED and err is clear.
 * rotated and leaked stay false on every path. This note does not rotate
 * a holdout or reveal it.
 */
SwarmNotRotateResult SwarmNoteNotRotate(const SwarmNotRotate& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTROTATE_H
