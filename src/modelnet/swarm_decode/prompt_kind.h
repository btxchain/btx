// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_PROMPT_KIND_H
#define BITCOIN_MODELNET_SWARM_DECODE_PROMPT_KIND_H

#include <modelnet/swarm_decode/book.h>

#include <string>

namespace modelnet {

/**
 * How one Prompt attempt relates to the book.
 * Store is the only result that may be written. The other results store nothing.
 * The book is not modified. text() is not modified.
 */
enum class SwarmDecodePromptKind {
    Store,
    Session,
    PrivateData,
    Prompt,
    Held,
    Replay,
};

/**
 * Classify one Prompt attempt.
 * An unknown session is Session.
 * A private prompt is PrivateData, including when the text is empty.
 * An empty public prompt is Prompt.
 * A different public prompt on a session that already has one is Held.
 * The same public prompt again is Replay.
 */
SwarmDecodePromptKind SwarmDecodeClassifyPrompt(const SwarmDecodeBook& book,
                                                const std::string& session,
                                                const std::string& text,
                                                bool is_private);

/** Refusal code for a non-store kind, or nullptr for Store. */
const char* SwarmDecodePromptKindCode(SwarmDecodePromptKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_PROMPT_KIND_H
