// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_PROMPT_H
#define BITCOIN_MODELNET_SWARM_DECODE_PROMPT_H

#include <modelnet/swarm_decode/book.h>

#include <string>

namespace modelnet {

/**
 * Store one public prompt on an open session.
 * An unknown session is SESSION.
 * A private prompt is PRIVATE_DATA and stores nothing.
 * An empty public prompt is PROMPT and stores nothing.
 * A second different public prompt is HELD and keeps the first.
 * The same public prompt again is REPLAY and keeps the first.
 * A stored prompt is not copied into text(). Pull is what appends bytes.
 * A production engine name may store a prompt. That store does not emit bytes.
 */
bool SwarmDecodePromptApply(SwarmDecodeBook& book,
                            const std::string& session,
                            const std::string& text,
                            bool is_private,
                            std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_PROMPT_H
