// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOCHECKPOINT_H
#define BTX_MODELNET_SWARM_NOCHECKPOINT_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_publish asks this note to publish a
 * checkpoint. checkpoint_saved is a flag, not a publication.
 *
 * This note does not publish a checkpoint. published stays false on every
 * path. A step that did not save a checkpoint does not publish one.
 */
struct SwarmNoCheckpoint {
    std::string run_id;
    bool checkpoint_saved{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a run. published stays false on every path.
 */
struct SwarmNoCheckpointResult {
    std::string code;
    bool published{false};
};

/**
 * Note a run without publishing a checkpoint.
 * Order, first match wins: an empty run_id is CHECK.
 * A step that did not save a checkpoint is NO_CHECKPOINT, even when
 * want_publish is true.
 * want_publish after a saved checkpoint is HELD and err is cleared.
 * Otherwise the note is NOTED and err is clear.
 * published stays false on every path. A step that did not save a
 * checkpoint does not publish one.
 */
SwarmNoCheckpointResult SwarmNoteNoCheckpoint(const SwarmNoCheckpoint& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOCHECKPOINT_H
