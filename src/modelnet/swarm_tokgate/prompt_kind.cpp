// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/prompt_kind.h>

#include <modelnet/swarm_tokgate/blank.h>
#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/codes.h>
#include <modelnet/swarm_tokgate/held.h>
#include <modelnet/swarm_tokgate/privacy.h>
#include <modelnet/swarm_tokgate/replay.h>

#include <string>

namespace modelnet {

SwarmTokenGatePromptKind SwarmTokenGateClassifyPrompt(const SwarmTokenGateBook& book,
                                                      const std::string& session,
                                                      const std::string& text,
                                                      bool is_private)
{
    if (!book.open(session)) return SwarmTokenGatePromptKind::Session;
    if (SwarmTokenGatePrivatePrompt(is_private)) return SwarmTokenGatePromptKind::PrivateData;
    if (SwarmTokenGateBlank(text)) return SwarmTokenGatePromptKind::Prompt;
    if (SwarmTokenGatePromptReplay(book, session, text, is_private)) {
        return SwarmTokenGatePromptKind::Replay;
    }
    if (SwarmTokenGatePromptHeld(book, session, text, is_private)) return SwarmTokenGatePromptKind::Held;
    return SwarmTokenGatePromptKind::Store;
}

const char* SwarmTokenGatePromptKindCode(SwarmTokenGatePromptKind kind)
{
    switch (kind) {
    case SwarmTokenGatePromptKind::Store:
        return nullptr;
    case SwarmTokenGatePromptKind::Session:
        return kSwarmTokenGateSession;
    case SwarmTokenGatePromptKind::PrivateData:
        return kSwarmTokenGatePrivateData;
    case SwarmTokenGatePromptKind::Prompt:
        return kSwarmTokenGatePrompt;
    case SwarmTokenGatePromptKind::Replay:
        return kSwarmTokenGateReplay;
    case SwarmTokenGatePromptKind::Held:
        return kSwarmTokenGateHeld;
    }
    return kSwarmTokenGatePrompt;
}

} // namespace modelnet
