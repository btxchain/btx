// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGLOBALCKPT2_H
#define BTX_MODELNET_SWARM_NOTNOGLOBALCKPT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one island admission. want_build asks this note to
 * build a global checkpoint for that admission.
 *
 * Island admission builds no global checkpoint. built and bytes_moved stay
 * false on every path.
 */
struct SwarmNotNoGlobalCkpt2 {
    std::string run_id;
    bool want_build{false};
};

/**
 * Outcome of noting an island admission. built and bytes_moved stay false
 * on every path: island admission builds no global checkpoint.
 */
struct SwarmNotNoGlobalCkpt2Result {
    std::string code;
    bool built{false};
    bool bytes_moved{false};
};

/**
 * Note an island admission without building a global checkpoint. Order,
 * first match wins: an empty run_id is RUN. want_build is HELD. Otherwise
 * the note is NOTED and err is clear. built and bytes_moved stay false on
 * every path. Island admission builds no global checkpoint.
 */
SwarmNotNoGlobalCkpt2Result SwarmNoteNotNoGlobalCkpt2(const SwarmNotNoGlobalCkpt2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGLOBALCKPT2_H
