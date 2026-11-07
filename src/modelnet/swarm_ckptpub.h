// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CKPTPUB_H
#define BTX_MODELNET_SWARM_CKPTPUB_H

#include <string>

namespace modelnet {

/**
 * A local note about one checkpoint candidate. Writing a checkpoint,
 * saving GPU state, and publishing are not provided.
 */
struct SwarmCheckpointNote {
    std::string checkpoint_id;
    std::string digest;
    bool body_complete{false};
    bool interrupted{false};
};

/**
 * A local checkpoint note. published stays false: a note is not a
 * written checkpoint, not a GPU save, and not a publication.
 */
struct SwarmCheckpointNoteResult {
    bool published{false};
    std::string code;
};

/**
 * Order, first match wins: an empty checkpoint_id or digest is CHECKPOINT.
 * A note whose body is not complete is TRUNCATED, including when
 * interrupted is also true. An interrupted note is INTERRUPTED. Otherwise
 * the note is NOTED and err is clear. published stays false on every
 * path. This records a local note. It does not write a checkpoint, does
 * not save GPU state, and does not publish. No files are written.
 */
SwarmCheckpointNoteResult SwarmNoteCheckpoint(const SwarmCheckpointNote& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CKPTPUB_H
