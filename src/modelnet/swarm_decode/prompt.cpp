// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/prompt.h>

#include <modelnet/swarm_decode/book.h>
#include <modelnet/swarm_decode/codes.h>
#include <modelnet/swarm_decode/prompt_kind.h>

#include <string>

namespace modelnet {

bool SwarmDecodePromptApply(SwarmDecodeBook& book,
                            const std::string& session,
                            const std::string& text,
                            bool is_private,
                            std::string& err)
{
    const SwarmDecodePromptKind kind = SwarmDecodeClassifyPrompt(book, session, text, is_private);
    const char* code = SwarmDecodePromptKindCode(kind);
    if (code != nullptr) {
        err = code;
        return false;
    }
    if (!book.store_prompt(session, text)) {
        if (!book.open(session)) {
            err = kSwarmDecodeSession;
            return false;
        }
        if (!book.prompt_stored(session)) {
            err = kSwarmDecodePrompt;
            return false;
        }
        if (book.stored_prompt(session) == text) {
            err = kSwarmDecodeReplay;
            return false;
        }
        err = kSwarmDecodeHeld;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
