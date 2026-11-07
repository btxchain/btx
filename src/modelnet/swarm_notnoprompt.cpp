// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprompt.h>

#include <string>

namespace modelnet {

SwarmNotNoPromptResult SwarmNoteNotNoPrompt(const SwarmNotNoPrompt& note, std::string& err)
{
    // This note stores no prompt.
    SwarmNotNoPromptResult result;
    result.stored = false;
    result.bytes_moved = false;
    if (note.prompt_id.empty()) {
        result.code = "PROMPT";
        result.stored = false;
        result.bytes_moved = false;
        err = "PROMPT";
        return result;
    }
    if (note.want_store) {
        result.code = "NOT_STORED";
        result.stored = false;
        result.bytes_moved = false;
        err = "NOT_STORED";
        return result;
    }
    result.code = "NOTED";
    result.stored = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
