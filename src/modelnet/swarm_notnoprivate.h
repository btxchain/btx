// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPRIVATE_H
#define BTX_MODELNET_SWARM_NOTNOPRIVATE_H

#include <string>

namespace modelnet {

/**
 * A local note about one prompt. private_prompt marks the prompt as
 * private. want_store asks this note to store the prompt.
 *
 * A private prompt is not stored by this note. stored and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoPrivate {
    std::string prompt_id;
    bool private_prompt{false};
    bool want_store{false};
};

/**
 * Outcome of noting a prompt. stored and bytes_moved stay false on every
 * path. A private prompt is not stored by this note.
 */
struct SwarmNotNoPrivateResult {
    std::string code;
    bool stored{false};
    bool bytes_moved{false};
};

/**
 * Note a prompt without storing it.
 * Order, first match wins:
 * 1. An empty prompt_id is PROMPT. stored stays false, bytes_moved
 *    stays false, and err is PROMPT.
 * 2. private_prompt is NOT_STORED, even when want_store is false.
 *    stored stays false, bytes_moved stays false, and err is
 *    NOT_STORED.
 * 3. want_store is NOT_STORED. stored stays false, bytes_moved stays
 *    false, and err is NOT_STORED.
 * 4. Otherwise the note is NOTED. stored stays false, bytes_moved
 *    stays false, and err is cleared.
 * A private prompt is not stored by this note.
 */
SwarmNotNoPrivateResult SwarmNoteNotNoPrivate(const SwarmNotNoPrivate& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPRIVATE_H
