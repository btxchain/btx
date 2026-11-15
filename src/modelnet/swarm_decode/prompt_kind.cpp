// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/prompt_kind.h>

#include <modelnet/swarm_decode/book.h>
#include <modelnet/swarm_decode/codes.h>

#include <string>

namespace modelnet {

SwarmDecodePromptKind SwarmDecodeClassifyPrompt(const SwarmDecodeBook& book,
                                                const std::string& session,
                                                const std::string& text,
                                                bool is_private)
{
    if (!book.open(session)) return SwarmDecodePromptKind::Session;
    if (is_private) return SwarmDecodePromptKind::PrivateData;
    if (text.empty()) return SwarmDecodePromptKind::Prompt;
    if (book.prompt_stored(session)) {
        if (book.stored_prompt(session) == text) return SwarmDecodePromptKind::Replay;
        return SwarmDecodePromptKind::Held;
    }
    return SwarmDecodePromptKind::Store;
}

const char* SwarmDecodePromptKindCode(SwarmDecodePromptKind kind)
{
    if (kind == SwarmDecodePromptKind::Session) return kSwarmDecodeSession;
    if (kind == SwarmDecodePromptKind::PrivateData) return kSwarmDecodePrivateData;
    if (kind == SwarmDecodePromptKind::Prompt) return kSwarmDecodePrompt;
    if (kind == SwarmDecodePromptKind::Held) return kSwarmDecodeHeld;
    if (kind == SwarmDecodePromptKind::Replay) return kSwarmDecodeReplay;
    return nullptr;
}

} // namespace modelnet
