// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_private.h>

#include <string>

namespace modelnet {

SwarmPrivatePromptResult SwarmNotePrivatePrompt(const SwarmPrivatePrompt& prompt, std::string& err)
{
    SwarmPrivatePromptResult result;
    result.accepted = false;
    if (prompt.node_id.empty()) {
        result.code = "PROMPT";
        result.accepted = false;
        err = "PROMPT";
        return result;
    }
    // A private prompt stays off without an operator allowance.
    if (prompt.want_private && !prompt.operator_allows) {
        result.code = "PRIVATE";
        result.accepted = false;
        err = "PRIVATE";
        return result;
    }
    // An operator allowance still does not make this note accept a
    // private prompt. Nothing is stored and nothing is sent.
    if (prompt.want_private) {
        result.code = "HELD";
        result.accepted = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    err.clear();
    return result;
}

} // namespace modelnet
