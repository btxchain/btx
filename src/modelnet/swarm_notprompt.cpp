// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notprompt.h>

#include <string>

namespace modelnet {

SwarmNotPromptResult SwarmNoteNotPrompt(const SwarmNotPrompt& note, std::string& err)
{
    SwarmNotPromptResult result;
    result.accepted = false;
    result.stored = false;
    if (note.prompt_id.empty()) {
        result.code = "PROMPT";
        result.accepted = false;
        result.stored = false;
        err = "PROMPT";
        return result;
    }
    // This note does not store a private prompt.
    if (note.want_private) {
        result.code = "PRIVATE_DATA";
        result.accepted = false;
        result.stored = false;
        err = "PRIVATE_DATA";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    result.stored = false;
    err.clear();
    return result;
}

} // namespace modelnet
