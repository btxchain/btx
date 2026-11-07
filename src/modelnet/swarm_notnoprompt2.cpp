// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprompt2.h>

#include <string>

namespace modelnet {

SwarmNotNoPrompt2Result SwarmNoteNotNoPrompt2(const SwarmNotNoPrompt2& note, std::string& err)
{
    SwarmNotNoPrompt2Result result;
    result.enabled = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.enabled = false;
        err = "NODE";
        return result;
    }
    // Private prompts stay off.
    if (note.want_enable) {
        result.code = "HELD";
        result.enabled = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.enabled = false;
    err.clear();
    return result;
}

} // namespace modelnet
