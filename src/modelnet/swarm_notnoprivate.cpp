// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprivate.h>

#include <string>

namespace modelnet {

SwarmNotNoPrivateResult SwarmNoteNotNoPrivate(const SwarmNotNoPrivate& note, std::string& err)
{
    SwarmNotNoPrivateResult result;
    result.stored = false;
    result.bytes_moved = false;
    // A private prompt is not stored by this note.
    if (note.prompt_id.empty()) {
        result.code = "PROMPT";
        result.stored = false;
        result.bytes_moved = false;
        err = "PROMPT";
        return result;
    }
    if (note.private_prompt) {
        result.code = "NOT_STORED";
        result.stored = false;
        result.bytes_moved = false;
        err = "NOT_STORED";
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
