// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/prompt.h>

#include <modelnet/swarm_tokgate/blank.h>
#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/codes.h>
#include <modelnet/swarm_tokgate/privacy.h>
#include <modelnet/swarm_tokgate/prompt_kind.h>
#include <modelnet/swarm_tokgate/same.h>

#include <string>

namespace modelnet {

bool SwarmTokenGatePromptApply(SwarmTokenGateBook& book,
                               const std::string& session,
                               const std::string& text,
                               bool is_private,
                               std::string& err)
{
    const SwarmTokenGatePromptKind kind = SwarmTokenGateClassifyPrompt(book, session, text, is_private);
    const char* code = SwarmTokenGatePromptKindCode(kind);
    if (code != nullptr) {
        err = code;
        return false;
    }
    if (SwarmTokenGatePrivatePrompt(is_private)) {
        err = kSwarmTokenGatePrivateData;
        return false;
    }
    if (SwarmTokenGateBlank(text)) {
        err = kSwarmTokenGatePrompt;
        return false;
    }
    if (!book.store_prompt(session, text)) {
        if (!book.open(session)) {
            err = kSwarmTokenGateSession;
            return false;
        }
        if (book.prompt_stored(session) && SwarmTokenGateSame(book.stored_prompt(session), text)) {
            err = kSwarmTokenGateReplay;
            return false;
        }
        if (book.prompt_stored(session)) {
            err = kSwarmTokenGateHeld;
            return false;
        }
        err = kSwarmTokenGatePrompt;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
