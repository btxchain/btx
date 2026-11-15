// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPROMPT_H
#define BTX_MODELNET_SWARM_NOTPROMPT_H

#include <string>

namespace modelnet {

/**
 * A local note about a prompt. want_private asks this note to store a
 * private prompt.
 *
 * This note does not store a private prompt, so accepted and stored stay
 * false on every path.
 */
struct SwarmNotPrompt {
    std::string prompt_id;
    bool want_private{false};
};

/**
 * Outcome of noting a prompt. accepted and stored stay false on every path.
 */
struct SwarmNotPromptResult {
    std::string code;
    bool accepted{false};
    bool stored{false};
};

/**
 * Note that this note does not store a private prompt.
 * Order, first match wins: an empty prompt_id is PROMPT. want_private is
 * PRIVATE_DATA. Otherwise the note is NOTED and err is clear.
 * accepted and stored stay false on every path. This note does not store
 * a private prompt.
 */
SwarmNotPromptResult SwarmNoteNotPrompt(const SwarmNotPrompt& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPROMPT_H
