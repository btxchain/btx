// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCHECK_H
#define BTX_MODELNET_SWARM_NOTNOCHECK_H

#include <string>

namespace modelnet {

/**
 * A local note about one checkpoint. saved says a checkpoint was stored.
 * want_resume asks this note to resume from it.
 *
 * This note does not resume a checkpoint and moves no bytes. An unsaved
 * checkpoint is not resumed. resumed and bytes_moved stay false on every
 * path.
 */
struct SwarmNotNoCheck {
    std::string step_id;
    bool saved{false};
    bool want_resume{false};
};

/**
 * Outcome of noting a checkpoint. resumed and bytes_moved stay false on
 * every path: this note resumes nothing and moves no bytes.
 */
struct SwarmNotNoCheckResult {
    std::string code;
    bool resumed{false};
    bool bytes_moved{false};
};

/**
 * Note a checkpoint without resuming it or moving bytes.
 * Order, first match wins: an empty step_id is STEP. A note that is not
 * saved is NO_CHECKPOINT, even when want_resume is false. want_resume is
 * NO_CHECKPOINT. Otherwise the note is NOTED and err is cleared.
 * resumed and bytes_moved stay false on every path. An unsaved checkpoint
 * is not resumed.
 */
SwarmNotNoCheckResult SwarmNoteNotNoCheck(const SwarmNotNoCheck& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCHECK_H
