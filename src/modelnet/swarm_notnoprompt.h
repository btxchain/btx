// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPROMPT_H
#define BTX_MODELNET_SWARM_NOTNOPROMPT_H

#include <string>

namespace modelnet {

/**
 * A local note about one prompt. want_store asks this note to store the
 * prompt.
 *
 * This note stores no prompt. stored and bytes_moved stay false on every
 * path.
 */
struct SwarmNotNoPrompt {
    std::string prompt_id;
    bool want_store{false};
};

/**
 * Outcome of noting a prompt. stored and bytes_moved stay false on every
 * path: this note stores no prompt.
 */
struct SwarmNotNoPromptResult {
    std::string code;
    bool stored{false};
    bool bytes_moved{false};
};

/**
 * Note a prompt without storing it. Order, first match wins: an empty
 * prompt_id is PROMPT. want_store is NOT_STORED. Otherwise the note is
 * NOTED and err is cleared. stored and bytes_moved stay false on every
 * path. This note stores no prompt.
 */
SwarmNotNoPromptResult SwarmNoteNotNoPrompt(const SwarmNotNoPrompt& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPROMPT_H
