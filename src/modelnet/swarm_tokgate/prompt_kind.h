// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_PROMPT_KIND_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_PROMPT_KIND_H

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

/**
 * How one Prompt attempt relates to the book.
 * Store is the only result that may be written. The other results store nothing.
 * The book is not modified. text is a prompt, not generated output.
 */
enum class SwarmTokenGatePromptKind {
    Store,
    Session,
    PrivateData,
    Prompt,
    Replay,
    Held,
};

/**
 * Classify one Prompt attempt.
 * An unknown session is Session, including when the prompt is private or empty.
 * A private prompt on an open session is PrivateData.
 * An empty public prompt is Prompt.
 * The same public prompt already stored is Replay.
 * A different public prompt on a session that already has one is Held.
 */
SwarmTokenGatePromptKind SwarmTokenGateClassifyPrompt(const SwarmTokenGateBook& book,
                                                      const std::string& session,
                                                      const std::string& text,
                                                      bool is_private);

/** Refusal code for a non-store kind, or nullptr for Store. */
const char* SwarmTokenGatePromptKindCode(SwarmTokenGatePromptKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_PROMPT_KIND_H
